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
        tls_certs: Vec::new(),
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        h3_certs: Vec::new(),
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
        xhttp_path_vless: None,
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
                xhttp_path_vless: None,
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
                xhttp_path_vless: None,
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
                xhttp_path_vless: None,
                enabled: None,
            },
        ],
        method: CipherKind::Chacha20IetfPoly1305,
        access_key: Default::default(),
        tuning: Default::default(),
        session_resumption: Default::default(),
        http_fallback: None,
        sni_fallback: None,
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
    // WS-VLESS URI carries `alpn=h2,http/1.1` — the Ws carrier
    // appends `http/1.1` as the last-resort fallback so old clients
    // that cannot speak h2 Extended CONNECT still match a transport.
    // XHTTP keeps the shorter `alpn=h2` (no h1) because stream-one
    // returns 505 over HTTP/1.1 and listing it would invite a doomed
    // dial. Comma is percent-encoded (`%2C`); `/` in `http/1.1` is
    // also encoded (`http%2F1.1`).
    assert_eq!(
        artifacts[2].access_key_url.as_deref(),
        Some(
            "vless://550e8400-e29b-41d4-a716-446655440000@vpn.example.com:443?type=ws&security=tls&alpn=h2%2Chttp%2F1.1&path=%2Fcarol%2Fvless%20path&encryption=none#vpn:carol%20vless"
        )
    );
    assert_eq!(
        artifacts[2].yaml,
        "vless://550e8400-e29b-41d4-a716-446655440000@vpn.example.com:443?type=ws&security=tls&alpn=h2%2Chttp%2F1.1&path=%2Fcarol%2Fvless%20path&encryption=none#vpn:carol%20vless\n"
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
fn emits_xhttp_packet_up_and_stream_one_artifacts() {
    let mut config = sample_config();
    config.xhttp_path_vless = Some("/xh".into());
    config.users.push(UserEntry {
        id: "dave".into(),
        password: None,
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        vless_id: Some("750e8400-e29b-41d4-a716-446655440000".into()),
        ws_path_vless: None,
        xhttp_path_vless: None,
        enabled: None,
    });

    let artifacts = build_access_key_artifacts(&config, &sample_ak_config()).unwrap();

    let packet_up = artifacts
        .iter()
        .find(|a| a.config_filename == "dave-vless-xhttp.yaml")
        .expect("packet-up artifact emitted");
    assert!(
        packet_up
            .access_key_url
            .as_deref()
            .unwrap()
            .contains("mode=packet-up"),
        "packet-up URI carries mode=packet-up: {:?}",
        packet_up.access_key_url
    );
    assert!(
        packet_up
            .access_key_url
            .as_deref()
            .unwrap()
            .ends_with("#vpn:dave-xhttp")
    );

    let stream_one = artifacts
        .iter()
        .find(|a| a.config_filename == "dave-vless-xhttp-stream-one.yaml")
        .expect("stream-one artifact emitted");
    assert!(
        stream_one
            .access_key_url
            .as_deref()
            .unwrap()
            .contains("mode=stream-one"),
        "stream-one URI carries mode=stream-one: {:?}",
        stream_one.access_key_url
    );
    assert!(
        stream_one
            .access_key_url
            .as_deref()
            .unwrap()
            .ends_with("#vpn:dave-xhttp-stream-one")
    );

    // Both URIs carry an `alpn=` preference list when the carrier
    // rides TLS — without it, xray-family clients fall through to
    // HTTP/1.1 ALPN, where stream-one fails server-side (h1 cannot
    // full-duplex). Sample config has `h3_listen = None`, so the
    // list collapses to plain `h2`.
    for artifact in [packet_up, stream_one] {
        let url = artifact.access_key_url.as_deref().unwrap();
        assert!(
            url.contains("alpn=h2"),
            "{} URI must pin alpn=h2 (no h3 listener in sample): {:?}",
            artifact.config_filename,
            artifact.access_key_url,
        );
    }
}

#[test]
fn vless_uris_alpn_prefers_h3_when_quic_listener_enabled() {
    // When `[server.h3]` is configured, every TLS-carrying VLESS
    // URI (WS and XHTTP alike) advertises `h3,h2` so dual-stack
    // clients try QUIC first (lower-RTT carrier) and fall back to
    // h2 only when UDP/QUIC is blocked. Comma is percent-encoded on
    // the wire (`%2C`) per the URI spec; the assertion checks the
    // encoded form so a future change that accidentally drops the
    // encoding trips here. Both URI shapes are covered to pin the
    // shared `preferred_alpn_list` helper — a regression that fixes
    // one variant while breaking the other would now fail loudly.
    let mut config = sample_config();
    config.xhttp_path_vless = Some("/xh".into());
    config.h3_listen = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443));
    config.h3_cert_path = Some(std::path::PathBuf::from("/dev/null"));
    config.h3_key_path = Some(std::path::PathBuf::from("/dev/null"));
    config.users.push(UserEntry {
        id: "eve".into(),
        password: None,
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        vless_id: Some("850e8400-e29b-41d4-a716-446655440000".into()),
        ws_path_vless: Some("/eve/vless".into()),
        xhttp_path_vless: None,
        enabled: None,
    });

    let artifacts = build_access_key_artifacts(&config, &sample_ak_config()).unwrap();

    let xhttp = artifacts
        .iter()
        .find(|a| a.config_filename == "eve-vless-xhttp-stream-one.yaml")
        .expect("stream-one artifact emitted");
    let xhttp_url = xhttp.access_key_url.as_deref().unwrap();
    // XHTTP URI lists exactly `h3,h2` — `http/1.1` would invite a
    // 505 on stream-one, so it stays out.
    assert!(
        xhttp_url.contains("alpn=h3%2Ch2&"),
        "h3-enabled XHTTP URI must list `h3,h2` (no h1 trailer): {:?}",
        xhttp.access_key_url,
    );
    assert!(
        !xhttp_url.contains("http%2F1.1"),
        "XHTTP URI must NOT include http/1.1 in alpn: {:?}",
        xhttp.access_key_url,
    );

    let ws = artifacts
        .iter()
        .find(|a| a.config_filename == "eve-vless.yaml")
        .expect("WS-VLESS artifact emitted");
    let ws_url = ws.access_key_url.as_deref().unwrap();
    // WS-VLESS URI lists `h3,h2,http/1.1` — classic WS Upgrade
    // works as the last-resort fallback for old clients without
    // h2 Extended CONNECT support.
    assert!(
        ws_url.contains("alpn=h3%2Ch2%2Chttp%2F1.1"),
        "h3-enabled WS URI must list `h3,h2,http/1.1`: {:?}",
        ws.access_key_url,
    );
}

#[test]
fn vless_uris_skip_alpn_for_plain_http_scheme() {
    // ALPN is a TLS extension — emitting it for a `ws://` (plain
    // HTTP) deployment would just be noise xray clients ignore.
    // Pin the omission so a future refactor that always-on emits
    // it accidentally trips this test. Both WS and XHTTP shapes
    // are covered to keep the helper's TLS-only contract tight.
    let ak = AccessKeyConfig {
        public_scheme: "ws".into(),
        ..sample_ak_config()
    };
    let mut config = sample_config();
    config.xhttp_path_vless = Some("/xh".into());
    config.users.push(UserEntry {
        id: "frank".into(),
        password: None,
        fwmark: None,
        method: None,
        ws_path_tcp: None,
        ws_path_udp: None,
        vless_id: Some("950e8400-e29b-41d4-a716-446655440000".into()),
        ws_path_vless: Some("/frank/vless".into()),
        xhttp_path_vless: None,
        enabled: None,
    });

    let artifacts = build_access_key_artifacts(&config, &ak).unwrap();
    for filename in ["frank-vless-xhttp.yaml", "frank-vless.yaml"] {
        let artifact = artifacts
            .iter()
            .find(|a| a.config_filename == filename)
            .unwrap_or_else(|| panic!("artifact {filename:?} expected"));
        let url = artifact.access_key_url.as_deref().unwrap();
        assert!(
            !url.contains("alpn="),
            "plain-http deployment must not emit alpn= in {filename:?}: {:?}",
            artifact.access_key_url,
        );
    }
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
