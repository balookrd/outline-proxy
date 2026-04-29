use super::{
    build_access_key_artifacts, dynamic_access_key_url, normalize_host,
    render_written_access_key_report, sanitize_filename, write_access_key_artifacts,
};
use crate::config::{AccessKeyConfig, CipherKind, Config, UserEntry};
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
        h3_alpn: vec![crate::config::H3Alpn::H3],
        metrics_listen: None,
        metrics_path: "/metrics".into(),
        prefer_ipv4_upstream: false,
        outbound_ipv6_prefix: None,
        outbound_ipv6_interface: None,
        outbound_ipv6_refresh_secs: 30,
        ws_path_tcp: "/tcp".into(),
        ws_path_udp: "/udp".into(),
        ws_path_vless: Some("/vless path".into()),
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
        users: vec![
            UserEntry {
                id: "alice".into(),
                password: Some("secret-a".into()),
                fwmark: Some(1001),
                method: Some(CipherKind::Aes256Gcm),
                ws_path_tcp: Some("/alice/tcp".into()),
                ws_path_udp: Some("/alice/udp".into()),
                vless_id: None,
                ws_path_vless: None,
                enabled: None,
            },
            UserEntry {
                id: "bob".into(),
                password: Some("secret-b".into()),
                fwmark: Some(1002),
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                ws_path_vless: None,
                enabled: None,
            },
            UserEntry {
                id: "carol vless".into(),
                password: None,
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
                ws_path_vless: Some("/carol/vless path".into()),
                enabled: None,
            },
        ],
        method: CipherKind::Chacha20IetfPoly1305,
        access_key: Default::default(),
        tuning: Default::default(),
        session_resumption: Default::default(),
        config_path: None,
        control: None,
        dashboard: None,
    }
}

fn sample_ak_config() -> AccessKeyConfig {
    AccessKeyConfig {
        public_host: Some("vpn.example.com".into()),
        public_scheme: "wss".into(),
        access_key_url_base: Some("https://keys.example.com/outline".into()),
        access_key_file_extension: ".yaml".into(),
    }
}

#[test]
fn builds_outline_artifacts_for_all_users() {
    let artifacts = build_access_key_artifacts(&sample_config(), &sample_ak_config()).unwrap();

    assert_eq!(artifacts.len(), 3);
    assert_eq!(
        artifacts[0].access_key_url.as_deref(),
        Some("ssconf://keys.example.com/outline/alice.yaml")
    );
    assert!(artifacts[0].yaml.contains("url: \"wss://vpn.example.com/alice/tcp\""));
    assert!(artifacts[0].yaml.contains("url: \"wss://vpn.example.com/alice/udp\""));
    assert!(artifacts[0].yaml.contains("cipher: \"aes-256-gcm\""));
    assert!(artifacts[1].yaml.contains("cipher: \"chacha20-ietf-poly1305\""));
    assert_eq!(artifacts[2].config_filename, "carol_vless-vless.yaml");
    assert_eq!(
        artifacts[2].access_key_url.as_deref(),
        Some(
            "vless://550e8400-e29b-41d4-a716-446655440000@vpn.example.com:443?type=ws&security=tls&path=%2Fcarol%2Fvless%20path&encryption=none#vpn:carol%20vless"
        )
    );
    assert_eq!(
        artifacts[2].yaml,
        "vless://550e8400-e29b-41d4-a716-446655440000@vpn.example.com:443?type=ws&security=tls&path=%2Fcarol%2Fvless%20path&encryption=none#vpn:carol%20vless\n"
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
    let artifacts = build_access_key_artifacts(&sample_config(), &sample_ak_config()).unwrap();
    let output_dir = std::env::temp_dir().join(format!(
        "outline-ss-rust-access-key-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let written = write_access_key_artifacts(&artifacts, &output_dir).unwrap();

    assert_eq!(written.len(), 3);
    assert_eq!(
        std::fs::read_to_string(output_dir.join("alice.yaml")).unwrap(),
        artifacts[0].yaml
    );
    assert!(render_written_access_key_report(&written).contains("written_file:"));

    std::fs::remove_dir_all(output_dir).unwrap();
}

#[test]
fn builds_both_ss_and_vless_artifacts_for_combined_user() {
    let mut config = sample_config();
    config.users[0].vless_id = Some("650e8400-e29b-41d4-a716-446655440000".into());

    let artifacts = build_access_key_artifacts(&config, &sample_ak_config()).unwrap();

    assert!(
        artifacts
            .iter()
            .any(|artifact| artifact.config_filename == "alice.yaml")
    );
    assert!(
        artifacts
            .iter()
            .any(|artifact| artifact.config_filename == "alice-vless.yaml")
    );
}

#[test]
fn uses_custom_access_key_file_extension() {
    let ak = AccessKeyConfig {
        access_key_file_extension: ".txt".into(),
        ..sample_ak_config()
    };

    let artifacts = build_access_key_artifacts(&sample_config(), &ak).unwrap();

    assert_eq!(artifacts[0].config_filename, "alice.txt");
    assert_eq!(
        artifacts[0].access_key_url.as_deref(),
        Some("ssconf://keys.example.com/outline/alice.txt")
    );
    assert_eq!(artifacts[2].config_filename, "carol_vless-vless.txt");
}
