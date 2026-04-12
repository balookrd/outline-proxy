use std::{
    fs,
    path::{Path, PathBuf},
};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenAccessKeyArtifact {
    pub user_id: String,
    pub path: PathBuf,
    pub config_url: Option<String>,
    pub access_key_url: Option<String>,
}

pub fn build_access_key_artifacts(config: &Config) -> Result<Vec<AccessKeyArtifact>> {
    if config.listen.is_none() {
        bail!("Outline access keys require the websocket listen listener to be configured");
    }
    let users = config.user_entries()?;
    let public_host = config
        .public_host
        .as_deref()
        .ok_or_else(|| anyhow!("--public-host is required to generate Outline access keys"))?;

    if !matches!(config.public_scheme.as_str(), "ws" | "wss") {
        bail!("--public-scheme must be either ws or wss");
    }

    users
        .into_iter()
        .map(|user| build_user_artifact(config, &user, public_host))
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

fn build_user_artifact(
    config: &Config,
    user: &UserEntry,
    public_host: &str,
) -> Result<AccessKeyArtifact> {
    let config_filename = format!(
        "{}{}",
        sanitize_filename(&user.id),
        config.access_key_file_extension
    );
    let config_url = config
        .access_key_url_base
        .as_deref()
        .map(|base| join_url(base, &config_filename))
        .transpose()?;
    let access_key_url = config_url
        .as_deref()
        .map(dynamic_access_key_url)
        .transpose()?;
    let method = user.effective_method(config.method);
    let tcp_url = websocket_url(
        &config.public_scheme,
        public_host,
        user.effective_ws_path_tcp(&config.ws_path_tcp),
    );
    let udp_url = websocket_url(
        &config.public_scheme,
        public_host,
        user.effective_ws_path_udp(&config.ws_path_udp),
    );

    Ok(AccessKeyArtifact {
        user_id: user.id.clone(),
        config_filename,
        config_url,
        access_key_url,
        yaml: render_outline_yaml(method.as_str(), &user.password, &tcp_url, &udp_url),
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
        build_access_key_artifacts, dynamic_access_key_url, normalize_host,
        render_written_access_key_report, sanitize_filename, write_access_key_artifacts,
    };
    use crate::config::{CipherKind, Config, UserEntry};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sample_config() -> Config {
        Config {
            listen: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000)),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            client_active_ttl_secs: 300,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            http_root_auth: false,
            http_root_realm: "outline-ss-rust".into(),
            public_host: Some("vpn.example.com".into()),
            public_scheme: "wss".into(),
            access_key_url_base: Some("https://keys.example.com/outline".into()),
            access_key_file_extension: ".yaml".into(),
            print_access_keys: false,
            write_access_keys_dir: None,
            password: None,
            fwmark: None,
            users: vec![
                UserEntry {
                    id: "alice".into(),
                    password: "secret-a".into(),
                    fwmark: Some(1001),
                    method: Some(CipherKind::Aes256Gcm),
                    ws_path_tcp: Some("/alice/tcp".into()),
                    ws_path_udp: Some("/alice/udp".into()),
                },
                UserEntry {
                    id: "bob".into(),
                    password: "secret-b".into(),
                    fwmark: Some(1002),
                    method: None,
                    ws_path_tcp: None,
                    ws_path_udp: None,
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
                .contains("url: \"wss://vpn.example.com/alice/tcp\"")
        );
        assert!(
            artifacts[0]
                .yaml
                .contains("url: \"wss://vpn.example.com/alice/udp\"")
        );
        assert!(artifacts[0].yaml.contains("cipher: \"aes-256-gcm\""));
        assert!(
            artifacts[1]
                .yaml
                .contains("cipher: \"chacha20-ietf-poly1305\"")
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

    #[test]
    fn writes_outline_artifacts_to_directory() {
        let artifacts = build_access_key_artifacts(&sample_config()).unwrap();
        let output_dir = std::env::temp_dir().join(format!(
            "outline-ss-rust-access-key-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let written = write_access_key_artifacts(&artifacts, &output_dir).unwrap();

        assert_eq!(written.len(), 2);
        assert_eq!(
            std::fs::read_to_string(output_dir.join("alice.yaml")).unwrap(),
            artifacts[0].yaml
        );
        assert!(render_written_access_key_report(&written).contains("written_file:"));

        std::fs::remove_dir_all(output_dir).unwrap();
    }

    #[test]
    fn uses_custom_access_key_file_extension() {
        let mut config = sample_config();
        config.access_key_file_extension = ".txt".into();

        let artifacts = build_access_key_artifacts(&config).unwrap();

        assert_eq!(artifacts[0].config_filename, "alice.txt");
        assert_eq!(
            artifacts[0].access_key_url.as_deref(),
            Some("ssconf://keys.example.com/outline/alice.txt")
        );
    }
}
