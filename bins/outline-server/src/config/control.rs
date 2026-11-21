use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::{cli::ConfigArgs, file::FileConfig};

const DEFAULT_ACCESS_KEYS_PYTHON: &str = "python3";
const DEFAULT_ACCESS_KEYS_TIMEOUT_SECS: u64 = 15;
const MAX_ACCESS_KEYS_TIMEOUT_SECS: u64 = 120;

#[derive(Clone)]
#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub struct ControlConfig {
    pub listen: SocketAddr,
    pub token: String,
    pub access_keys_generator: Option<PathBuf>,
    pub access_keys_python: PathBuf,
    pub access_keys_timeout_secs: u64,
}

// Hand-written so a `{:?}` of the config can never put the token in a log.
impl std::fmt::Debug for ControlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlConfig")
            .field("listen", &self.listen)
            .field("token", &"<redacted>")
            .field("access_keys_generator", &self.access_keys_generator)
            .field("access_keys_python", &self.access_keys_python)
            .field("access_keys_timeout_secs", &self.access_keys_timeout_secs)
            .finish()
    }
}

fn clean_optional_path(path: Option<&Path>, field: &str) -> Result<Option<PathBuf>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let text = path.to_string_lossy();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{field} cannot be empty");
    }
    Ok(Some(PathBuf::from(trimmed)))
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
        (Some(t), None) => {
            let trimmed = t.trim().to_owned();
            if trimmed.is_empty() {
                anyhow::bail!("control.token cannot be empty");
            }
            Some(trimmed)
        },
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

    let access_keys_generator = clean_optional_path(
        file_control.and_then(|c| c.access_keys_generator.as_deref()),
        "control.access_keys_generator",
    )?;
    let access_keys_python = clean_optional_path(
        file_control.and_then(|c| c.access_keys_python.as_deref()),
        "control.access_keys_python",
    )?
    .unwrap_or_else(|| PathBuf::from(DEFAULT_ACCESS_KEYS_PYTHON));
    let access_keys_timeout_secs = file_control
        .and_then(|c| c.access_keys_timeout_secs)
        .unwrap_or(DEFAULT_ACCESS_KEYS_TIMEOUT_SECS);
    if !(1..=MAX_ACCESS_KEYS_TIMEOUT_SECS).contains(&access_keys_timeout_secs) {
        anyhow::bail!(
            "control.access_keys_timeout_secs must be between 1 and {MAX_ACCESS_KEYS_TIMEOUT_SECS}"
        );
    }

    match (listen, token) {
        (Some(listen), Some(token)) => Ok(Some(ControlConfig {
            listen,
            token,
            access_keys_generator,
            access_keys_python,
            access_keys_timeout_secs,
        })),
        (None, None) => Ok(None),
        (Some(_), None) => {
            anyhow::bail!("control.listen requires control.token or control.token_file")
        },
        (None, Some(_)) => anyhow::bail!("control.token requires control.listen"),
    }
}

#[cfg(test)]
#[path = "tests/control.rs"]
mod tests;
