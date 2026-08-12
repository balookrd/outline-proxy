//! Configuration for the UI service.
//!
//! Deliberately its own file rather than a slice of a data-plane config: this
//! process has no uplinks, no listeners and no users of its own. It knows only
//! where to listen, how to authenticate a browser, and which control APIs to
//! aggregate.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Default seconds between browser refreshes; mirrors the value both dashboards
/// shipped with.
const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 5;
/// Default per-request timeout when talking to an instance control API.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
pub struct UiConfig {
    pub listen: SocketAddr,
    /// Guards the listener itself. Mandatory: see `tests/config.rs`.
    pub token: String,
    pub request_timeout_secs: u64,
    pub refresh_interval_secs: u64,
    pub allowed_hosts: Vec<String>,
    pub ws: Vec<InstanceConfig>,
    pub ss: Vec<InstanceConfig>,
}

#[derive(Debug, Clone)]
pub struct InstanceConfig {
    pub name: String,
    pub control_url: String,
    pub token: String,
}

#[derive(Deserialize)]
struct FileConfig {
    server: ServerSection,
    #[serde(default)]
    ws: TreeSection,
    #[serde(default)]
    ss: TreeSection,
}

#[derive(Deserialize)]
struct ServerSection {
    listen: SocketAddr,
    token: Option<String>,
    token_file: Option<PathBuf>,
    request_timeout_secs: Option<u64>,
    refresh_interval_secs: Option<u64>,
    #[serde(default)]
    allowed_hosts: Vec<String>,
}

#[derive(Deserialize, Default)]
struct TreeSection {
    #[serde(default)]
    instances: Vec<InstanceSection>,
}

#[derive(Deserialize)]
struct InstanceSection {
    name: String,
    control_url: String,
    token: Option<String>,
    token_file: Option<PathBuf>,
}

/// Reads a secret from either the literal or the file form. Trailing whitespace
/// is stripped: secret mounts and `echo` both add a newline, and carrying it
/// into an `Authorization` header turns every request into an unexplainable 401.
fn resolve_secret(
    literal: Option<String>,
    file: Option<PathBuf>,
    what: &str,
) -> Result<Option<String>> {
    match (literal, file) {
        (Some(_), Some(_)) => bail!("{what}: set either token or token_file, not both"),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("{what}: failed to read {}", path.display()))?;
            Ok(Some(raw.trim_end().to_string()))
        },
        (None, None) => Ok(None),
    }
}

impl UiConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let file: FileConfig =
            toml::from_str(&raw).with_context(|| format!("invalid config {}", path.display()))?;

        let token = resolve_secret(file.server.token, file.server.token_file, "[server]")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[server]: token or token_file is required — this listener grants every \
                         configured instance token to whoever reaches it"
                )
            })?;

        let convert = |tree: TreeSection, label: &str| -> Result<Vec<InstanceConfig>> {
            tree.instances
                .into_iter()
                .map(|i| {
                    let what = format!("[[{label}.instances]] {}", i.name);
                    let token = resolve_secret(i.token, i.token_file, &what)?.ok_or_else(|| {
                        anyhow::anyhow!("{what}: token or token_file is required")
                    })?;
                    Ok(InstanceConfig {
                        name: i.name,
                        control_url: i.control_url,
                        token,
                    })
                })
                .collect()
        };

        Ok(Self {
            listen: file.server.listen,
            token,
            request_timeout_secs: file
                .server
                .request_timeout_secs
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
            refresh_interval_secs: file
                .server
                .refresh_interval_secs
                .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECS),
            allowed_hosts: file.server.allowed_hosts,
            ws: convert(file.ws, "ws")?,
            ss: convert(file.ss, "ss")?,
        })
    }
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
