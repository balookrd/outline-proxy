use std::{net::SocketAddr, path::Path};

use anyhow::Result;

use super::{cli::ConfigArgs, file::FileConfig};

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub struct ControlConfig {
    pub listen: SocketAddr,
    pub token: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub struct DashboardConfig {
    pub listen: SocketAddr,
    pub request_timeout_secs: u64,
    pub refresh_interval_secs: u64,
    pub instances: Vec<DashboardInstanceConfig>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub struct DashboardInstanceConfig {
    pub name: String,
    pub control_url: String,
    pub token: String,
}

pub(super) fn resolve_dashboard_config(
    file: &FileConfig,
    config_dir: &Path,
) -> Result<Option<DashboardConfig>> {
    let Some(dashboard) = file.dashboard.as_ref() else {
        return Ok(None);
    };
    if dashboard.enabled == Some(false) {
        return Ok(None);
    }

    let listen = dashboard
        .listen
        .ok_or_else(|| anyhow::anyhow!("dashboard enabled but dashboard.listen is not set"))?;
    let instances = dashboard
        .instances
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("dashboard enabled but dashboard.instances is empty"))?;
    if instances.is_empty() {
        anyhow::bail!("dashboard enabled but dashboard.instances is empty");
    }

    let mut loaded = Vec::with_capacity(instances.len());
    for (idx, server) in instances.iter().enumerate() {
        let name = server
            .name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("dashboard server #{idx} has no name"))?;
        let control_url = server
            .control_url
            .clone()
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("dashboard server {name:?} has no control_url"))?;
        if !(control_url.starts_with("http://") || control_url.starts_with("https://")) {
            anyhow::bail!(
                "dashboard server {name:?} uses unsupported control_url {control_url:?}; \
                 only http:// and https:// control listeners are supported"
            );
        }
        control_url.parse::<hyper::Uri>().map_err(|error| {
            anyhow::anyhow!("invalid dashboard server {name:?} control_url: {error}")
        })?;

        let inline_token = server.token.clone().filter(|token| !token.is_empty());
        let file_token = match server.token_file.as_ref() {
            Some(path) => {
                let resolved = if path.is_absolute() {
                    path.clone()
                } else {
                    config_dir.join(path)
                };
                let contents = std::fs::read_to_string(&resolved).map_err(|error| {
                    anyhow::anyhow!(
                        "failed to read dashboard token file {}: {error}",
                        resolved.display()
                    )
                })?;
                let trimmed = contents.trim().to_owned();
                if trimmed.is_empty() {
                    anyhow::bail!("dashboard token file {} is empty", resolved.display());
                }
                Some(trimmed)
            },
            None => None,
        };
        if inline_token.is_some() && file_token.is_some() {
            anyhow::bail!(
                "dashboard server {name:?}: specify either token or token_file, not both"
            );
        }
        let token = inline_token
            .or(file_token)
            .ok_or_else(|| anyhow::anyhow!("dashboard server {name:?} has no token"))?;

        loaded.push(DashboardInstanceConfig { name, control_url, token });
    }

    Ok(Some(DashboardConfig {
        listen,
        request_timeout_secs: dashboard.request_timeout_secs.unwrap_or(15).max(1),
        refresh_interval_secs: dashboard.refresh_interval_secs.unwrap_or(10).max(1),
        instances: loaded,
    }))
}

pub(super) fn resolve_control_config(
    args: &ConfigArgs,
    file: &FileConfig,
) -> Result<Option<ControlConfig>> {
    let file_control = file.control.as_ref();
    let listen = args.control_listen.or_else(|| file_control.and_then(|c| c.listen));
    let token_literal = args
        .control_token
        .clone()
        .or_else(|| file_control.and_then(|c| c.token.clone()));
    let token_file = args
        .control_token_file
        .clone()
        .or_else(|| file_control.and_then(|c| c.token_file.clone()));

    let token = match (token_literal, token_file) {
        (Some(t), None) => Some(t),
        (None, Some(path)) => {
            let contents = std::fs::read_to_string(&path).map_err(|error| {
                anyhow::anyhow!("failed to read control token file {}: {error}", path.display())
            })?;
            let trimmed = contents.trim().to_owned();
            if trimmed.is_empty() {
                anyhow::bail!("control token file {} is empty", path.display());
            }
            Some(trimmed)
        },
        (Some(_), Some(_)) => {
            anyhow::bail!("specify either control.token or control.token_file, not both")
        },
        (None, None) => None,
    };

    match (listen, token) {
        (Some(listen), Some(token)) => Ok(Some(ControlConfig { listen, token })),
        (None, None) => Ok(None),
        (Some(_), None) => {
            anyhow::bail!("control.listen requires control.token or control.token_file")
        },
        (None, Some(_)) => anyhow::bail!("control.token requires control.listen"),
    }
}
