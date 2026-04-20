use std::path::Path;

use anyhow::{Context, Result, bail};
use tokio::fs;

use super::args::Args;
use super::compat::normalize_outline_section;
use super::schema::{ConfigFile, ControlSection};
use super::types::{AppConfig, ControlConfig, MetricsConfig};

mod auth;
mod balancing;
mod groups;
mod h2;
mod probe;
mod routing;
mod tcp_timeouts;
#[cfg(feature = "tun")]
mod tun;
mod uplinks;

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
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        Some(match ext {
            "yaml" | "yml" => serde_yml::from_str::<ConfigFile>(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?,
            _ => toml::from_str::<ConfigFile>(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?,
        })
    } else {
        None
    };

    let socks5 = file.as_ref().and_then(|f| f.socks5.as_ref());
    let outline = file.as_ref().and_then(normalize_outline_section);
    let metrics_section = file.as_ref().and_then(|f| f.metrics.as_ref());
    let control_section = file.as_ref().and_then(|f| f.control.as_ref());
    #[cfg(feature = "tun")]
    let tun_section = file.as_ref().and_then(|f| f.tun.as_ref());
    let h2_section = file.as_ref().and_then(|f| f.h2.as_ref());
    let udp_recv_buf_bytes = file.as_ref().and_then(|f| f.udp_recv_buf_bytes);
    let udp_send_buf_bytes = file.as_ref().and_then(|f| f.udp_send_buf_bytes);

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
    let control = load_control_config(control_section, args, config_dir).await?;
    #[cfg(not(feature = "control"))]
    if control.is_some() {
        bail!(
            "control listener requested (via [control], --control-listen, or CONTROL_LISTEN) \
             but this build has the `control` feature disabled; rebuild with --features control"
        );
    }
    #[cfg(feature = "tun")]
    let tun = tun::load_tun_config(tun_section, args)?;
    let h2 = h2::load_h2_config(h2_section);
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

    Ok(AppConfig {
        listen,
        socks5_auth,
        groups,
        routing,
        metrics,
        control,
        #[cfg(feature = "tun")]
        tun,
        h2,
        udp_recv_buf_bytes,
        udp_send_buf_bytes,
        direct_fwmark,
        state_path,
        tcp_timeouts,
    })
}

async fn load_control_config(
    section: Option<&ControlSection>,
    args: &Args,
    config_dir: &Path,
) -> Result<Option<ControlConfig>> {
    let listen = args.control_listen.or_else(|| section.and_then(|s| s.listen));
    let cli_token = args.control_token.clone().filter(|t| !t.is_empty());
    let inline_token = section
        .and_then(|s| s.token.clone())
        .filter(|t| !t.is_empty());
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
        (Some(listen), Some(token)) => Ok(Some(ControlConfig { listen, token })),
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
