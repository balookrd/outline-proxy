use std::net::SocketAddr;

use anyhow::Result;

use super::{cli::ConfigArgs, file::FileConfig};

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub struct ControlConfig {
    pub listen: SocketAddr,
    pub token: String,
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
