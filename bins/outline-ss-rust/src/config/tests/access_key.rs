use super::{
    build_access_key_artifacts, dynamic_access_key_url, normalize_host,
    render_written_access_key_report, sanitize_filename, write_access_key_artifacts,
};
use crate::config::{AccessKeyConfig, CipherKind, Config, UserEntry};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn sample_config() -> Config {
    Config {
        listen: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000)),
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
        outbound_ipv6_prefix_interface: None,
        outbound_ipv6_refresh_secs: 30,
        outbound_ipv6_sticky: false,
        outbound_ipv6_sticky_ttl_secs: 1800,
        ws_path_tcp: "/tcp".into(),
        ws_path_udp: "/udp".into(),
        ws_path_ss: None,
        ws_path_vless: Some("/vless path".into()),
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
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
                ws_path_ss: None,
                vless_id: None,
                ws_path_vless: None,
                xhttp_path_vless: None,
                xhttp_path_tcp: None,
                xhttp_path_udp: None,
                xhttp_path_ss: None,
                enabled: None,
                aliases: None,
            },
            UserEntry {
                id: "bob".into(),
                password: Some("secret-b".into()),
                fwmark: Some(1002),
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                ws_path_ss: None,
                vless_id: None,
                ws_path_vless: None,
                xhttp_path_vless: None,
                xhttp_path_tcp: None,
                xhttp_path_udp: None,
                xhttp_path_ss: None,
                enabled: None,
                aliases: None,
            },
            UserEntry {
                id: "carol vless".into(),
                password: None,
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                ws_path_ss: None,
                vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
                ws_path_vless: Some("/carol/vless path".into()),
                xhttp_path_vless: None,
                xhttp_path_tcp: None,
                xhttp_path_udp: None,
                xhttp_path_ss: None,
                enabled: None,
                aliases: None,
            },
        ],
        method: CipherKind::Chacha20IetfPoly1305,
        access_key: Default::default(),
        tuning: Default::default(),
        session_resumption: Default::default(),
        padding: Default::default(),
        http_fallback: None,
        sni_fallback: None,
        cluster: None,
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
    assert_eq!(artifacts[2].config_filename, "carol_vless-vless-ws.yaml");
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
            "vless://550e8400-e29b-41d4-a716-446655440000@vpn.example.com:443?type=ws&security=tls&alpn=h2%2Chttp%2F1.1&path=%2Fcarol%2Fvless%20path&encryption=none#vpn:carol%20vless-vless-ws"
        )
    );
    assert_eq!(
        artifacts[2].yaml,
        "vless://550e8400-e29b-41d4-a716-446655440000@vpn.example.com:443?type=ws&security=tls&alpn=h2%2Chttp%2F1.1&path=%2Fcarol%2Fvless%20path&encryption=none#vpn:carol%20vless-vless-ws\n"
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
            .any(|artifact| artifact.config_filename == "alice-vless-ws.yaml")
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
        ws_path_ss: None,
        vless_id: Some("750e8400-e29b-41d4-a716-446655440000".into()),
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    });

    let artifacts = build_access_key_artifacts(&config, &sample_ak_config()).unwrap();

    let packet_up = artifacts
        .iter()
        .find(|a| a.config_filename == "dave-vless-xhttp-packet-up.yaml")
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
            .ends_with("#vpn:dave-vless-xhttp-packet-up")
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
            .ends_with("#vpn:dave-vless-xhttp-stream-one")
    );

    // Both URIs carry an `alpn=` preference list when the carrier
    // rides TLS — without it, xray-family clients fall through to
    // HTTP/1.1 ALPN, where stream-one fails server-side (h1 cannot
    // full-duplex). Sample config has `h3_listen = None`, so the
    // baseline is `h2`. The two modes diverge on the trailer:
    // packet-up appends `http/1.1` (each packet is its own short
    // request, so h1 is a viable floor), stream-one omits it
    // (would invite a 505).
    let packet_up_url = packet_up.access_key_url.as_deref().unwrap();
    assert!(
        packet_up_url.contains("alpn=h2%2Chttp%2F1.1"),
        "packet-up URI must list `h2,http/1.1`: {:?}",
        packet_up.access_key_url,
    );
    let stream_one_url = stream_one.access_key_url.as_deref().unwrap();
    assert!(
        stream_one_url.contains("alpn=h2&"),
        "stream-one URI must list exactly `h2` (no h1 trailer): {:?}",
        stream_one.access_key_url,
    );
    assert!(
        !stream_one_url.contains("http%2F1.1"),
        "stream-one URI must NOT include http/1.1 in alpn: {:?}",
        stream_one.access_key_url,
    );
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
        ws_path_ss: None,
        vless_id: Some("850e8400-e29b-41d4-a716-446655440000".into()),
        ws_path_vless: Some("/eve/vless".into()),
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    });

    let artifacts = build_access_key_artifacts(&config, &sample_ak_config()).unwrap();

    let stream_one = artifacts
        .iter()
        .find(|a| a.config_filename == "eve-vless-xhttp-stream-one.yaml")
        .expect("stream-one artifact emitted");
    let stream_one_url = stream_one.access_key_url.as_deref().unwrap();
    // Stream-one URI lists exactly `h3,h2` — `http/1.1` would invite
    // a 505 on the dial because h1 cannot full-duplex stream-one's
    // single bidi POST, so it stays out.
    assert!(
        stream_one_url.contains("alpn=h3%2Ch2&"),
        "h3-enabled stream-one URI must list `h3,h2` (no h1 trailer): {:?}",
        stream_one.access_key_url,
    );
    assert!(
        !stream_one_url.contains("http%2F1.1"),
        "stream-one URI must NOT include http/1.1 in alpn: {:?}",
        stream_one.access_key_url,
    );

    let packet_up = artifacts
        .iter()
        .find(|a| a.config_filename == "eve-vless-xhttp-packet-up.yaml")
        .expect("packet-up artifact emitted");
    let packet_up_url = packet_up.access_key_url.as_deref().unwrap();
    // Packet-up URI lists `h3,h2,http/1.1` — each packet is its own
    // short request/response, so h1 is a viable last-resort path
    // when a CDN strips h2 ALPN. The trailer matches the WS URI so
    // both XHTTP modes' sibling URIs offer the right floor for
    // their respective server-side handler contracts.
    assert!(
        packet_up_url.contains("alpn=h3%2Ch2%2Chttp%2F1.1"),
        "h3-enabled packet-up URI must list `h3,h2,http/1.1`: {:?}",
        packet_up.access_key_url,
    );

    let ws = artifacts
        .iter()
        .find(|a| a.config_filename == "eve-vless-ws.yaml")
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
        ws_path_ss: None,
        vless_id: Some("950e8400-e29b-41d4-a716-446655440000".into()),
        ws_path_vless: Some("/frank/vless".into()),
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        enabled: None,
        aliases: None,
    });

    let artifacts = build_access_key_artifacts(&config, &ak).unwrap();
    for filename in ["frank-vless-xhttp-packet-up.yaml", "frank-vless-ws.yaml"] {
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
    assert_eq!(artifacts[2].config_filename, "carol_vless-vless-ws.txt");
}

#[test]
fn emits_ss_share_links_for_combined_path_user() {
    use base64::Engine;

    let mut config = sample_config();
    // Global combined-path SS — both legs share one base path per carrier.
    config.ws_path_ss = Some("/ss ws".into());
    config.xhttp_path_ss = Some("/ss xhttp".into());

    let artifacts = build_access_key_artifacts(&config, &sample_ak_config()).unwrap();

    // bob pins no per-user split paths, so the global combined default applies
    // to both carriers: Outline YAML + ss-ws + ss-xhttp packet-up + stream-one.
    let bob: Vec<_> = artifacts.iter().filter(|a| a.user_id == "bob").collect();
    assert_eq!(bob.len(), 4);

    let ss_ws = artifacts
        .iter()
        .find(|a| a.config_filename == "bob-ss-ws.yaml")
        .expect("ss-ws artifact");
    let url = ss_ws.access_key_url.as_deref().unwrap();
    assert!(url.starts_with("ss://"), "{url}");
    assert!(url.contains("@vpn.example.com:443?"), "{url}");
    assert!(url.contains("type=ws"), "{url}");
    assert!(url.contains("security=tls"), "{url}");
    assert!(url.contains("alpn=h2"), "{url}");
    assert!(url.contains("path=%2Fss%20ws"), "{url}");
    assert!(url.ends_with("#vpn:bob-ss-ws"), "{url}");
    assert_eq!(ss_ws.yaml, format!("{url}\n"));

    // SIP002 userinfo decodes back to `method:password` (bob → global cipher).
    let userinfo = url.trim_start_matches("ss://").split('@').next().unwrap();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(userinfo)
        .unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), "chacha20-ietf-poly1305:secret-b");

    let ss_xhttp = artifacts
        .iter()
        .find(|a| a.config_filename == "bob-ss-xhttp-packet-up.yaml")
        .expect("ss-xhttp packet-up artifact");
    let xhttp_url = ss_xhttp.access_key_url.as_deref().unwrap();
    assert!(xhttp_url.contains("type=xhttp"), "{xhttp_url}");
    assert!(xhttp_url.contains("mode=packet-up"), "{xhttp_url}");
    assert!(xhttp_url.contains("path=%2Fss%20xhttp"), "{xhttp_url}");

    let ss_xhttp_so = artifacts
        .iter()
        .find(|a| a.config_filename == "bob-ss-xhttp-stream-one.yaml")
        .expect("ss-xhttp stream-one artifact");
    assert!(
        ss_xhttp_so
            .access_key_url
            .as_deref()
            .unwrap()
            .contains("mode=stream-one")
    );

    // alice pins per-user split `ws_path_tcp`/`ws_path_udp`, so "specific beats
    // general" opts her WS leg out of the global combined path — no ss-ws — but
    // her XHTTP leg (no per-user split) still picks up the combined default.
    assert!(artifacts.iter().all(|a| a.config_filename != "alice-ss-ws.yaml"));
    assert!(
        artifacts
            .iter()
            .any(|a| a.config_filename == "alice-ss-xhttp-packet-up.yaml")
    );
}

#[test]
fn no_ss_share_link_without_combined_path() {
    // sample_config has only split tcp/udp paths — no ws_path_ss / xhttp_path_ss
    // — so SS users get just the Outline YAML, no ss:// link.
    let artifacts = build_access_key_artifacts(&sample_config(), &sample_ak_config()).unwrap();
    assert!(
        artifacts.iter().all(|a| !a.config_filename.contains("-ss-")),
        "no ss:// artifacts expected for split-path-only deployment"
    );
}
