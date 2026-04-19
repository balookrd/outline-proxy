use anyhow::{Result, anyhow, bail};
use socks5_proto::{Socks5AuthConfig, Socks5AuthUserConfig};

use super::super::args::Args;
use super::super::schema::Socks5Section;

pub(super) fn load_socks5_auth_config(
    socks5: Option<&Socks5Section>,
    args: &Args,
) -> Result<Option<Socks5AuthConfig>> {
    let cli_username = args.socks5_username.clone();
    let cli_password = args.socks5_password.clone();

    if cli_username.is_some() || cli_password.is_some() {
        return match (cli_username, cli_password) {
            (Some(username), Some(password)) => Ok(Some(Socks5AuthConfig {
                users: vec![validate_socks5_auth_user(
                    Socks5AuthUserConfig { username, password },
                    "CLI socks5 auth user",
                )?],
            })),
            (Some(_), None) => {
                bail!(
                    "missing socks5 password: pass --socks5-password together with --socks5-username"
                )
            },
            (None, Some(_)) => {
                bail!(
                    "missing socks5 username: pass --socks5-username together with --socks5-password"
                )
            },
            (None, None) => unreachable!("checked above"),
        };
    }

    let Some(socks5) = socks5 else {
        return Ok(None);
    };

    let users = match (&socks5.users, &socks5.username, &socks5.password) {
        (Some(users), None, None) => users
            .iter()
            .enumerate()
            .map(|(index, user)| {
                let username = user.username.clone().ok_or_else(|| {
                    anyhow!("missing socks5 user username in [socks5].users entry {}", index + 1)
                })?;
                let password = user.password.clone().ok_or_else(|| {
                    anyhow!("missing socks5 user password in [socks5].users entry {}", index + 1)
                })?;
                validate_socks5_auth_user(
                    Socks5AuthUserConfig { username, password },
                    &format!("socks5 user {}", index + 1),
                )
            })
            .collect::<Result<Vec<_>>>()?,
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            bail!(
                "use either [socks5].username/password for a single user or [[socks5.users]] for multiple users, not both"
            )
        },
        (None, Some(username), Some(password)) => vec![validate_socks5_auth_user(
            Socks5AuthUserConfig {
                username: username.clone(),
                password: password.clone(),
            },
            "socks5 auth user",
        )?],
        (None, Some(_), None) => {
            bail!("missing socks5 password: set [socks5].password together with [socks5].username")
        },
        (None, None, Some(_)) => {
            bail!("missing socks5 username: set [socks5].username together with [socks5].password")
        },
        (None, None, None) => Vec::new(),
    };

    if users.is_empty() {
        return Ok(None);
    }

    Ok(Some(Socks5AuthConfig { users }))
}

fn validate_socks5_auth_user(
    user: Socks5AuthUserConfig,
    context_label: &str,
) -> Result<Socks5AuthUserConfig> {
    if user.username.len() > u8::MAX as usize {
        bail!("{context_label} username is too long; maximum is 255 bytes");
    }
    if user.password.len() > u8::MAX as usize {
        bail!("{context_label} password is too long; maximum is 255 bytes");
    }
    Ok(user)
}
