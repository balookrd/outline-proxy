use anyhow::{Result, anyhow, bail};

use crate::config::{Config, UserEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyArtifact {
    pub user_id: String,
    pub config_filename: String,
    pub config_url: Option<String>,
    pub access_key_url: Option<String>,
    pub yaml: String,
}

pub fn build_access_key_artifacts(config: &Config) -> Result<Vec<AccessKeyArtifact>> {
    let users = config.user_entries()?;
    let public_host = config
        .public_host
        .as_deref()
        .ok_or_else(|| anyhow!("--public-host is required to generate Outline access keys"))?;

    if !matches!(config.public_scheme.as_str(), "ws" | "wss") {
        bail!("--public-scheme must be either ws or wss");
    }

    let tcp_url = websocket_url(&config.public_scheme, public_host, &config.ws_path);
    let udp_url = websocket_url(&config.public_scheme, public_host, &config.udp_ws_path);

    users
        .into_iter()
        .map(|user| build_user_artifact(config, &user, &tcp_url, &udp_url))
        .collect()
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

fn build_user_artifact(
    config: &Config,
    user: &UserEntry,
    tcp_url: &str,
    udp_url: &str,
) -> Result<AccessKeyArtifact> {
    let config_filename = format!("{}.yaml", sanitize_filename(&user.id));
    let config_url = config
        .access_key_url_base
        .as_deref()
        .map(|base| join_url(base, &config_filename))
        .transpose()?;
    let access_key_url = config_url
        .as_deref()
        .map(dynamic_access_key_url)
        .transpose()?;

    Ok(AccessKeyArtifact {
        user_id: user.id.clone(),
        config_filename,
        config_url,
        access_key_url,
        yaml: render_outline_yaml(config.method.as_str(), &user.password, tcp_url, udp_url),
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
    format!(
        "{scheme}://{}{}",
        normalize_host(host),
        normalize_path(path)
    )
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

    if let Some((addr, port)) = host.rsplit_once(':') {
        if addr.parse::<std::net::Ipv6Addr>().is_ok() && port.chars().all(|ch| ch.is_ascii_digit())
        {
            return format!("[{addr}]:{port}");
        }
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

    if output.is_empty() {
        "user".to_owned()
    } else {
        output
    }
}

fn yaml_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::{
        build_access_key_artifacts, dynamic_access_key_url, normalize_host, sanitize_filename,
    };
    use crate::config::{CipherKind, Config, UserEntry};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sample_config() -> Config {
        Config {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000),
            ws_path: "/tcp".into(),
            udp_ws_path: "/udp".into(),
            public_host: Some("vpn.example.com".into()),
            public_scheme: "wss".into(),
            access_key_url_base: Some("https://keys.example.com/outline".into()),
            print_access_keys: false,
            password: None,
            fwmark: None,
            users: vec![
                UserEntry {
                    id: "alice".into(),
                    password: "secret-a".into(),
                    fwmark: Some(1001),
                },
                UserEntry {
                    id: "bob".into(),
                    password: "secret-b".into(),
                    fwmark: Some(1002),
                },
            ],
            method: CipherKind::Chacha20IetfPoly1305,
        }
    }

    #[test]
    fn builds_outline_artifacts_for_all_users() {
        let artifacts = build_access_key_artifacts(&sample_config()).unwrap();

        assert_eq!(artifacts.len(), 2);
        assert_eq!(
            artifacts[0].access_key_url.as_deref(),
            Some("ssconf://keys.example.com/outline/alice.yaml")
        );
        assert!(
            artifacts[0]
                .yaml
                .contains("url: \"wss://vpn.example.com/tcp\"")
        );
        assert!(
            artifacts[0]
                .yaml
                .contains("url: \"wss://vpn.example.com/udp\"")
        );
    }

    #[test]
    fn converts_https_url_to_ssconf() {
        assert_eq!(
            dynamic_access_key_url("https://keys.example.com/alice.yaml").unwrap(),
            "ssconf://keys.example.com/alice.yaml"
        );
    }

    #[test]
    fn sanitizes_filenames() {
        assert_eq!(sanitize_filename("alice/admin"), "alice_admin");
    }

    #[test]
    fn wraps_ipv6_public_host_for_urls() {
        assert_eq!(normalize_host("2001:db8::10"), "[2001:db8::10]");
        assert_eq!(normalize_host("2001:db8::10:443"), "[2001:db8::10]:443");
        assert_eq!(normalize_host("[2001:db8::10]:443"), "[2001:db8::10]:443");
    }
}
