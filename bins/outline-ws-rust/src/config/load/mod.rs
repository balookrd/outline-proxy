use std::path::Path;

use anyhow::{Context, Result, bail};
use tokio::fs;

use super::args::Args;
use super::compat::normalize_outline_section;
use super::schema::{
    ConfigFile, ControlSection, DashboardSection, PaddingSection, ReverseListenerSection,
};
use super::types::{
    AppConfig, ControlConfig, DashboardConfig, DashboardInstanceConfig, MetricsConfig,
    PaddingConfig, ReverseListenerConfig, ReversePeerConfig, ReversePeerKind,
};

mod auth;
mod balancing;
mod groups;
mod h2;
mod probe;
mod quic;
mod routing;
mod tcp_timeouts;
#[cfg(feature = "tun")]
mod tun;
mod uplinks;

#[cfg(feature = "control")]
pub(crate) use uplinks::validate_uplink_section;

#[cfg(test)]
mod tests;

const DIRECT_TARGET: &str = "direct";
const DROP_TARGET: &str = "drop";
const DEFAULT_GROUP: &str = "default";

pub async fn load_config(path: &Path, args: &Args) -> Result<AppConfig> {
    let file = if path.exists() {
        let raw = fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        Some(
            toml::from_str::<ConfigFile>(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?,
        )
    } else {
        None
    };

    let socks5 = file.as_ref().and_then(|f| f.socks5.as_ref());
    let outline = file.as_ref().and_then(normalize_outline_section);
    let metrics_section = file.as_ref().and_then(|f| f.metrics.as_ref());
    let control_section = file.as_ref().and_then(|f| f.control.as_ref());
    let dashboard_section = file.as_ref().and_then(|f| f.dashboard.as_ref());
    #[cfg(feature = "tun")]
    let tun_section = file.as_ref().and_then(|f| f.tun.as_ref());
    let h2_section = file.as_ref().and_then(|f| f.h2.as_ref());
    let udp_recv_buf_bytes = file.as_ref().and_then(|f| f.udp_recv_buf_bytes);
    let udp_send_buf_bytes = file.as_ref().and_then(|f| f.udp_send_buf_bytes);
    let prefer_public_ipv6_src = file.as_ref().and_then(|f| f.prefer_public_ipv6_src);

    let listen = args.listen.or_else(|| socks5.and_then(|s| s.listen));
    let socks5_auth = auth::load_socks5_auth_config(socks5, args)?;

    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));

    let groups = groups::load_groups(outline.as_ref(), file.as_ref(), args)?;
    let routing = routing::load_routing_config(file.as_ref(), &groups, config_dir)?;

    let metrics = args
        .metrics_listen
        .or_else(|| metrics_section.and_then(|section| section.listen))
        .map(|listen| MetricsConfig { listen });
    #[cfg(not(feature = "metrics"))]
    if metrics.is_some() {
        bail!(
            "metrics listener requested (via [metrics] or --metrics-listen) but this build has \
             the `metrics` feature disabled; rebuild with --features metrics"
        );
    }
    let control = load_control_config(control_section, args, config_dir, path).await?;
    let dashboard = load_dashboard_config(dashboard_section, config_dir).await?;
    #[cfg(not(feature = "control"))]
    if control.is_some() {
        bail!(
            "control listener requested (via [control], --control-listen, or CONTROL_LISTEN) \
             but this build has the `control` feature disabled; rebuild with --features control"
        );
    }
    #[cfg(not(feature = "dashboard"))]
    if dashboard.is_some() {
        bail!(
            "dashboard listener requested (via [dashboard]) but this build has the `dashboard` \
             feature disabled; rebuild with --features dashboard"
        );
    }
    #[cfg(feature = "tun")]
    let tun = tun::load_tun_config(tun_section, args)?;
    let h2 = h2::load_h2_config(h2_section);
    let quic = quic::load_quic_config(file.as_ref().and_then(|f| f.quic.as_ref()));
    let tcp_timeouts =
        tcp_timeouts::load_tcp_timeouts(file.as_ref().and_then(|f| f.tcp_timeouts.as_ref()));

    #[cfg(feature = "tun")]
    if listen.is_none() && tun.is_none() {
        bail!("no ingress configured: set --listen / [socks5].listen and/or configure [tun]");
    }
    #[cfg(not(feature = "tun"))]
    if listen.is_none() {
        bail!("no ingress configured: set --listen / [socks5].listen");
    }

    let direct_fwmark = file.as_ref().and_then(|f| f.direct_fwmark);
    let direct_ipv6_prefix_interface =
        file.as_ref().and_then(|f| f.direct_ipv6_prefix_interface.clone());
    // Default = `Strategy::None`, which keeps WS / XHTTP wire shape
    // byte-identical to pre-knob builds. Opt-in via `fingerprint_profile`
    // in the top-level config; serde already turns the string aliases
    // ("stable", "random", "off", …) into the right enum variant.
    // CLI / env (`--fingerprint-profile` / `OUTLINE_FINGERPRINT_PROFILE`)
    // wins over the TOML key, mirroring how `--listen` / `--metrics-listen`
    // shadow their `[socks5]` / `[metrics]` siblings. Per-uplink
    // overrides are independent and still apply on top of whichever
    // process-wide value lands here.
    let fingerprint_profile = args
        .fingerprint_profile
        .or_else(|| file.as_ref().and_then(|f| f.fingerprint_profile))
        .unwrap_or_default();

    // State file path priority: CLI flag > config key > default (config
    // path with extension replaced by ".state.toml"). Relative paths in
    // the config file are resolved against the config directory (not CWD);
    // `..` components are rejected to keep the path predictable.
    let state_path = if let Some(p) = args.state_path.clone() {
        Some(p)
    } else if let Some(p) = file.as_ref().and_then(|f| f.state_path.clone()) {
        Some(routing::resolve_config_path(&p, config_dir).context("invalid [state_path]")?)
    } else {
        Some(path.with_extension("state.toml"))
    };

    let reverse_listener =
        load_reverse_listener(file.as_ref().and_then(|f| f.reverse_listener.as_ref()), config_dir)?;

    // Default = disabled, which keeps WS / XHTTP wire shape byte-identical.
    // Config-synchronised with the server's `[padding]`; no CLI override
    // (it must match the server, so it lives in the config file only).
    let padding = resolve_padding(file.as_ref().and_then(|f| f.padding.as_ref()));

    Ok(AppConfig {
        listen,
        socks5_auth,
        groups,
        routing,
        metrics,
        control,
        dashboard,
        #[cfg(feature = "tun")]
        tun,
        h2,
        quic,
        udp_recv_buf_bytes,
        udp_send_buf_bytes,
        prefer_public_ipv6_src,
        direct_fwmark,
        direct_ipv6_prefix_interface,
        state_path,
        tcp_timeouts,
        fingerprint_profile,
        reverse_listener,
        padding,
    })
}

/// Resolve `[padding]` into runtime config. Absent → disabled (wire
/// unchanged). A `max_bytes` below `min_bytes`, or a `cover_jitter_max_ms`
/// below the min, is clamped up so the ranges stay well-formed (mirrors the
/// server's `PaddingConfig::from_section`).
fn resolve_padding(section: Option<&PaddingSection>) -> PaddingConfig {
    let d = PaddingConfig::default();
    let Some(s) = section else { return d };
    let min_bytes = s.min_bytes.unwrap_or(d.min_bytes);
    let max_bytes = s.max_bytes.unwrap_or(d.max_bytes).max(min_bytes);
    let cover_jitter_min_ms = s.cover_jitter_min_ms.unwrap_or(d.cover_jitter_min_ms);
    let cover_jitter_max_ms = s
        .cover_jitter_max_ms
        .unwrap_or(d.cover_jitter_max_ms)
        .max(cover_jitter_min_ms);
    PaddingConfig {
        enabled: s.enabled.unwrap_or(d.enabled),
        min_bytes,
        max_bytes,
        cover: s.cover.unwrap_or(d.cover),
        cover_jitter_min_ms,
        cover_jitter_max_ms,
        react_to_throttle: s.react_to_throttle.unwrap_or(d.react_to_throttle),
    }
}

/// Resolve `[reverse_listener]` into runtime config. `None` when absent or
/// `enabled = false`. Cert paths are resolved against the config dir; pin
/// strings and certs are validated by the listener at bind time. A peer
/// list is mandatory (the listener requires at least one allowed pin).
fn load_reverse_listener(
    section: Option<&ReverseListenerSection>,
    config_dir: &Path,
) -> Result<Option<ReverseListenerConfig>> {
    let Some(section) = section else { return Ok(None) };
    if section.enabled == Some(false) {
        return Ok(None);
    }
    if section.peers.is_empty() {
        bail!("[reverse_listener] requires at least one [[reverse_listener.peers]] entry");
    }
    let server_cert_path = routing::resolve_config_path(&section.server_cert_path, config_dir)
        .context("invalid [reverse_listener].server_cert_path")?;
    let server_key_path = routing::resolve_config_path(&section.server_key_path, config_dir)
        .context("invalid [reverse_listener].server_key_path")?;
    let peers = section
        .peers
        .iter()
        .enumerate()
        .map(|(idx, p)| resolve_reverse_peer(idx, p, &section.group))
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(ReverseListenerConfig {
        listen: section.listen,
        server_cert_path,
        server_key_path,
        group: section.group.as_str().into(),
        mtu: section.mtu.unwrap_or(true),
        max_peers: section.max_peers.unwrap_or(8).max(1),
        peers,
    }))
}

/// Resolve one reverse peer: pick the per-peer (or listener-default) group and
/// the protocol-specific credentials. Exactly one of `method` + `password`
/// (an SS peer) or `vless_id` (a VLESS peer) must be set.
fn resolve_reverse_peer(
    idx: usize,
    peer: &super::schema::ReversePeerSection,
    default_group: &str,
) -> Result<ReversePeerConfig> {
    // Per-peer `group` wins; otherwise fall back to the listener default so
    // existing single-group configs keep working.
    let group = peer.group.as_deref().unwrap_or(default_group).into();
    let kind = match (peer.method, peer.password.as_deref(), peer.vless_id.as_deref()) {
        (Some(method), Some(password), None) => {
            ReversePeerKind::Ss { method, password: password.to_string() }
        },
        (None, None, Some(vless_id)) => {
            let uuid = outline_transport::vless::parse_uuid(vless_id).with_context(|| {
                format!("[reverse_listener].peers[{idx}].vless_id is not a valid UUID")
            })?;
            ReversePeerKind::Vless { uuid }
        },
        _ => bail!(
            "[reverse_listener].peers[{idx}] must set exactly one of (method + password) \
             for an SS peer or vless_id for a VLESS peer"
        ),
    };
    Ok(ReversePeerConfig {
        client_cert_pin: peer.client_cert_pin.clone(),
        kind,
        group,
    })
}

async fn load_dashboard_config(
    section: Option<&DashboardSection>,
    config_dir: &Path,
) -> Result<Option<DashboardConfig>> {
    let Some(section) = section else {
        return Ok(None);
    };
    if section.enabled == Some(false) {
        return Ok(None);
    }

    let listen = section
        .listen
        .ok_or_else(|| anyhow::anyhow!("dashboard enabled but [dashboard].listen is not set"))?;
    let refresh_interval_secs = section.refresh_interval_secs.unwrap_or(5).max(1);
    let request_timeout_secs = section.request_timeout_secs.unwrap_or(15).max(1);
    let instances = section
        .instances
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("dashboard enabled but [dashboard].instances is empty"))?;
    if instances.is_empty() {
        bail!("dashboard enabled but [dashboard].instances is empty");
    }

    let mut loaded = Vec::with_capacity(instances.len());
    for (idx, instance) in instances.iter().enumerate() {
        let name = instance
            .name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("dashboard instance #{idx} has no name"))?;
        let control_url = instance
            .control_url
            .clone()
            .ok_or_else(|| anyhow::anyhow!("dashboard instance {name:?} has no control_url"))?;
        match control_url.scheme() {
            "http" | "https" => {},
            other => bail!(
                "dashboard instance {name:?} uses unsupported control_url scheme {other:?}; \
                 only http:// and https:// control listeners are supported"
            ),
        }
        let inline_token = instance.token.clone().filter(|token| !token.is_empty());
        let file_token = match instance.token_file.as_ref() {
            Some(path) => {
                let resolved = routing::resolve_config_path(path, config_dir)
                    .context("invalid [dashboard.instances].token_file")?;
                let raw = fs::read_to_string(&resolved).await.with_context(|| {
                    format!("failed to read dashboard token from {}", resolved.display())
                })?;
                let trimmed = raw.trim().to_owned();
                if trimmed.is_empty() {
                    bail!("dashboard token file {} is empty", resolved.display());
                }
                Some(trimmed)
            },
            None => None,
        };
        let token = inline_token
            .or(file_token)
            .ok_or_else(|| anyhow::anyhow!("dashboard instance {name:?} has no token"))?;

        loaded.push(DashboardInstanceConfig { name, control_url, token });
    }

    Ok(Some(DashboardConfig {
        listen,
        refresh_interval_secs,
        request_timeout_secs,
        instances: loaded,
    }))
}

async fn load_control_config(
    section: Option<&ControlSection>,
    args: &Args,
    config_dir: &Path,
    config_path: &Path,
) -> Result<Option<ControlConfig>> {
    let listen = args.control_listen.or_else(|| section.and_then(|s| s.listen));
    let cli_token = args.control_token.clone().filter(|t| !t.is_empty());
    let inline_token = section.and_then(|s| s.token.clone()).filter(|t| !t.is_empty());
    let file_token = match section.and_then(|s| s.token_file.as_ref()) {
        Some(path) => {
            let resolved = routing::resolve_config_path(path, config_dir)
                .context("invalid [control].token_file")?;
            let raw = fs::read_to_string(&resolved).await.with_context(|| {
                format!("failed to read control token from {}", resolved.display())
            })?;
            let trimmed = raw.trim().to_owned();
            if trimmed.is_empty() {
                bail!("control token file {} is empty", resolved.display());
            }
            Some(trimmed)
        },
        None => None,
    };
    let token = cli_token.or(inline_token).or(file_token);

    match (listen, token) {
        (None, None) => Ok(None),
        (Some(listen), Some(token)) => Ok(Some(ControlConfig {
            listen,
            token,
            config_path: if config_path.exists() {
                Some(config_path.to_path_buf())
            } else {
                None
            },
        })),
        (Some(_), None) => bail!(
            "control listener configured but no token set: provide [control].token, \
             [control].token_file, --control-token, or CONTROL_TOKEN"
        ),
        (None, Some(_)) => bail!(
            "control token set but no listener: provide [control].listen, \
             --control-listen, or CONTROL_LISTEN"
        ),
    }
}
