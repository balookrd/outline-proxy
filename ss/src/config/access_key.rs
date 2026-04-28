use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow, bail};

use super::{AccessKeyConfig, Config, UserEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyArtifact {
    pub user_id: String,
    pub config_filename: String,
    pub config_url: Option<String>,
    pub access_key_url: Option<String>,
    pub yaml: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenAccessKeyArtifact {
    pub user_id: String,
    pub path: PathBuf,
    pub config_url: Option<String>,
    pub access_key_url: Option<String>,
}

pub fn build_access_key_artifacts(
    config: &Config,
    ak: &AccessKeyConfig,
) -> Result<Vec<AccessKeyArtifact>> {
    if config.listen.is_none() {
        bail!("Outline access keys require the websocket listen listener to be configured");
    }
    let users = config.effective_users()?;
    let public_host = ak
        .public_host
        .as_deref()
        .ok_or_else(|| anyhow!("--public-host is required to generate client configs"))?;

    let mut artifacts = Vec::new();
    for user in users {
        if user.password.is_some() {
            artifacts.push(build_shadowsocks_user_artifact(config, ak, &user, public_host)?);
        }
        if user.vless_id.is_some() {
            artifacts.push(build_vless_user_artifact(config, ak, &user, public_host)?);
        }
    }
    Ok(artifacts)
}

#[cfg_attr(not(feature = "control"), allow(dead_code))]
pub fn build_access_key_artifacts_for_user(
    config: &Config,
    ak: &AccessKeyConfig,
    user: &UserEntry,
) -> Result<Vec<AccessKeyArtifact>> {
    if config.listen.is_none() {
        bail!("Outline access keys require the websocket listen listener to be configured");
    }
    let public_host = ak
        .public_host
        .as_deref()
        .ok_or_else(|| anyhow!("--public-host is required to generate client configs"))?;

    let mut user = user.clone();
    user.enabled = Some(true);
    let mut artifacts = Vec::new();
    if user.password.is_some() {
        artifacts.push(build_shadowsocks_user_artifact(config, ak, &user, public_host)?);
    }
    if user.vless_id.is_some() {
        artifacts.push(build_vless_user_artifact(config, ak, &user, public_host)?);
    }
    Ok(artifacts)
}

pub fn render_access_key_report(artifacts: &[AccessKeyArtifact]) -> String {
    let mut out = String::new();

    for (index, artifact) in artifacts.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }

        out.push_str(&format!("user: {}\n", artifact.user_id));
        out.push_str(&format!("config_file: {}\n", artifact.config_filename));
        if let Some(config_url) = &artifact.config_url {
            out.push_str(&format!("config_url: {}\n", config_url));
        }
        if let Some(access_key_url) = &artifact.access_key_url {
            out.push_str(&format!("access_key_url: {}\n", access_key_url));
        }
        out.push_str("config:\n");
        for line in artifact.yaml.lines() {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
    }

    out
}

pub fn write_access_key_artifacts(
    artifacts: &[AccessKeyArtifact],
    output_dir: &Path,
) -> Result<Vec<WrittenAccessKeyArtifact>> {
    fs::create_dir_all(output_dir)?;

    artifacts
        .iter()
        .map(|artifact| {
            let path = output_dir.join(&artifact.config_filename);
            fs::write(&path, &artifact.yaml)?;
            Ok(WrittenAccessKeyArtifact {
                user_id: artifact.user_id.clone(),
                path,
                config_url: artifact.config_url.clone(),
                access_key_url: artifact.access_key_url.clone(),
            })
        })
        .collect()
}

pub fn render_written_access_key_report(artifacts: &[WrittenAccessKeyArtifact]) -> String {
    let mut out = String::new();

    for (index, artifact) in artifacts.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }

        out.push_str(&format!("user: {}\n", artifact.user_id));
        out.push_str(&format!("written_file: {}\n", artifact.path.display()));
        if let Some(config_url) = &artifact.config_url {
            out.push_str(&format!("config_url: {}\n", config_url));
        }
        if let Some(access_key_url) = &artifact.access_key_url {
            out.push_str(&format!("access_key_url: {}\n", access_key_url));
        }
    }

    out
}

fn build_shadowsocks_user_artifact(
    config: &Config,
    ak: &AccessKeyConfig,
    user: &UserEntry,
    public_host: &str,
) -> Result<AccessKeyArtifact> {
    let config_filename =
        format!("{}{}", sanitize_filename(&user.id), ak.access_key_file_extension);
    let config_url = ak
        .access_key_url_base
        .as_deref()
        .map(|base| join_url(base, &config_filename))
        .transpose()?;
    let access_key_url = config_url.as_deref().map(dynamic_access_key_url).transpose()?;
    let method = user.effective_method(config.method);
    let tcp_url = websocket_url(
        &ak.public_scheme,
        public_host,
        user.effective_ws_path_tcp(&config.ws_path_tcp),
    );
    let udp_url = websocket_url(
        &ak.public_scheme,
        public_host,
        user.effective_ws_path_udp(&config.ws_path_udp),
    );

    Ok(AccessKeyArtifact {
        user_id: user.id.clone(),
        config_filename,
        config_url,
        access_key_url,
        yaml: render_outline_yaml(
            method.as_str(),
            user.password
                .as_deref()
                .expect("user_entries filters passwordless users"),
            &tcp_url,
            &udp_url,
        ),
    })
}

fn build_vless_user_artifact(
    config: &Config,
    ak: &AccessKeyConfig,
    user: &UserEntry,
    public_host: &str,
) -> Result<AccessKeyArtifact> {
    let vless_id = user.vless_id.as_deref().expect("checked by caller");
    let vless_path = user
        .effective_ws_path_vless(config.ws_path_vless.as_deref())
        .ok_or_else(|| anyhow!("vless_id for user {} requires ws_path_vless", user.id))?;
    let config_filename =
        format!("{}-vless{}", sanitize_filename(&user.id), ak.access_key_file_extension);
    let config_url = ak
        .access_key_url_base
        .as_deref()
        .map(|base| join_url(base, &config_filename))
        .transpose()?;
    let vless_url = vless_uri(vless_id, public_host, &ak.public_scheme, vless_path, &user.id);

    Ok(AccessKeyArtifact {
        user_id: user.id.clone(),
        config_filename,
        config_url,
        access_key_url: Some(vless_url.clone()),
        yaml: format!("{vless_url}\n"),
    })
}

fn render_outline_yaml(method: &str, password: &str, tcp_url: &str, udp_url: &str) -> String {
    format!(
        concat!(
            "transport:\n",
            "  $type: tcpudp\n",
            "  tcp:\n",
            "    $type: shadowsocks\n",
            "    endpoint:\n",
            "      $type: websocket\n",
            "      url: {tcp_url}\n",
            "    cipher: {cipher}\n",
            "    secret: {secret}\n",
            "  udp:\n",
            "    $type: shadowsocks\n",
            "    endpoint:\n",
            "      $type: websocket\n",
            "      url: {udp_url}\n",
            "    cipher: {cipher}\n",
            "    secret: {secret}\n"
        ),
        tcp_url = yaml_quote(tcp_url),
        udp_url = yaml_quote(udp_url),
        cipher = yaml_quote(method),
        secret = yaml_quote(password),
    )
}

fn websocket_url(scheme: &str, host: &str, path: &str) -> String {
    format!("{scheme}://{}{}", normalize_host(host), normalize_path(path))
}

fn vless_uri(id: &str, host: &str, scheme: &str, path: &str, label: &str) -> String {
    let security = if scheme == "wss" { "tls" } else { "none" };
    let default_port = if scheme == "wss" { 443 } else { 80 };
    format!(
        "vless://{}@{}?type=ws&security={security}&path={}&encryption=none#{}",
        id,
        vless_authority(host, default_port),
        percent_encode_query_value(&normalize_path(path)),
        percent_encode_fragment(label),
    )
}

fn vless_authority(host: &str, default_port: u16) -> String {
    let host = normalize_host(host);
    if host_has_port(&host) {
        host
    } else {
        format!("{host}:{default_port}")
    }
}

fn host_has_port(host: &str) -> bool {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.contains("]:");
    }
    host.rsplit_once(':')
        .is_some_and(|(_, port)| port.chars().all(|ch| ch.is_ascii_digit()))
}

fn percent_encode_query_value(value: &str) -> String {
    percent_encode(value, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    })
}

fn percent_encode_fragment(value: &str) -> String {
    percent_encode(value, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    })
}

fn percent_encode(value: &str, keep: impl Fn(u8) -> bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if keep(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

fn normalize_host(host: &str) -> String {
    if host.starts_with('[') || !host.contains(':') {
        return host.to_owned();
    }

    if let Some((addr, port)) = host.rsplit_once(':')
        && addr.parse::<std::net::Ipv6Addr>().is_ok()
        && port.chars().all(|ch| ch.is_ascii_digit())
    {
        return format!("[{addr}]:{port}");
    }

    format!("[{host}]")
}

fn join_url(base: &str, suffix: &str) -> Result<String> {
    if !(base.starts_with("https://") || base.starts_with("http://")) {
        bail!("--access-key-url-base must start with http:// or https://");
    }

    Ok(format!("{}/{}", base.trim_end_matches('/'), suffix))
}

fn dynamic_access_key_url(config_url: &str) -> Result<String> {
    if let Some(rest) = config_url.strip_prefix("https://") {
        return Ok(format!("ssconf://{rest}"));
    }
    if let Some(rest) = config_url.strip_prefix("http://") {
        return Ok(format!("ssconf://{rest}"));
    }
    if config_url.starts_with("ssconf://") {
        return Ok(config_url.to_owned());
    }

    bail!("config URL must start with http://, https:// or ssconf://");
}

fn sanitize_filename(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            output.push(ch);
        } else {
            output.push('_');
        }
    }

    if output.is_empty() { "user".to_owned() } else { output }
}

fn yaml_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
#[path = "tests/access_key.rs"]
mod tests;
