use super::super::{CipherKind, Config, default_http_root_realm};

fn base_config() -> Config {
    Config {
        config_path: None,
        control: None,
        dashboard: None,
        listen: Some("127.0.0.1:3000".parse().unwrap()),
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
        outbound_ipv6_sticky: false,
        outbound_ipv6_sticky_ttl_secs: 1800,
        ws_path_tcp: "/tcp".into(),
        ws_path_udp: "/udp".into(),
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_ss: None,
        xhttp_path_ss_udp: None,
        http_root_auth: false,
        http_root_realm: default_http_root_realm(),
        users: vec![super::super::UserEntry {
            id: "default".into(),
            password: Some("secret".into()),
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: None,
            ws_path_vless: None,
            xhttp_path_vless: None,
            xhttp_path_ss: None,
            xhttp_path_ss_udp: None,
            enabled: None,
        }],
        method: CipherKind::Chacha20IetfPoly1305,
        access_key: Default::default(),
        tuning: super::super::TuningProfile::LARGE,
        session_resumption: Default::default(),
        http_fallback: None,
        sni_fallback: None,
        reverse_tunnel: None,
    }
}

#[test]
fn requires_at_least_one_data_plane_listener() {
    let error = Config {
        listen: None,
        metrics_listen: Some("127.0.0.1:9090".parse().unwrap()),
        ..base_config()
    }
    .validate()
    .unwrap_err()
    .to_string();

    assert!(error.contains("configure at least one data-plane listener"));
}

#[test]
fn requires_explicit_h3_listener_when_enabled() {
    let error = Config {
        listen: None,
        h3_cert_path: Some("cert.pem".into()),
        h3_key_path: Some("key.pem".into()),
        ..base_config()
    }
    .validate()
    .unwrap_err()
    .to_string();

    assert!(error.contains("h3_listen must be configured explicitly"));
}

#[test]
fn allows_h3_listener_to_share_address_with_tcp_listener() {
    Config {
        h3_listen: Some("127.0.0.1:3000".parse().unwrap()),
        h3_cert_path: Some("cert.pem".into()),
        h3_key_path: Some("key.pem".into()),
        ..base_config()
    }
    .validate()
    .unwrap();
}

#[test]
fn rejects_http_root_auth_on_root_ws_path() {
    let error = Config {
        ws_path_tcp: "/".into(),
        http_root_auth: true,
        ..base_config()
    }
    .validate()
    .unwrap_err()
    .to_string();

    assert!(error.contains("http_root_auth requires all websocket paths to differ from '/'"));
}

#[test]
fn accepts_xhttp_path_ss_with_password_user() {
    // base_config has a password user, so an SS-over-XHTTP base path is valid.
    Config {
        xhttp_path_ss: Some("/ss".into()),
        ..base_config()
    }
    .validate()
    .unwrap();
}

#[test]
fn accepts_combined_ws_tcp_udp_path() {
    // The opt-in combined mode: one user shares a single base path for both
    // TCP and UDP. The hidden token bit splits them, so this must validate.
    Config {
        ws_path_tcp: "/both".into(),
        ws_path_udp: "/both".into(),
        ..base_config()
    }
    .validate()
    .unwrap();
}

#[test]
fn accepts_combined_xhttp_ss_path() {
    // Same idea on the XHTTP carrier: one ss base path for tcp and udp.
    Config {
        xhttp_path_ss: Some("/ssc".into()),
        xhttp_path_ss_udp: Some("/ssc".into()),
        ..base_config()
    }
    .validate()
    .unwrap();
}

#[test]
fn rejects_combined_ws_path_colliding_with_other_protocol() {
    // Combining tcp+udp on one path is allowed, but that path must still be
    // distinct from every OTHER protocol's path — a combined ws base sharing
    // a value with an ss-xhttp base is a conflict, not a second combine.
    let error = Config {
        ws_path_tcp: "/shared".into(),
        ws_path_udp: "/shared".into(),
        xhttp_path_ss: Some("/shared".into()),
        ..base_config()
    }
    .validate()
    .unwrap_err()
    .to_string();

    assert!(error.contains("must be distinct"), "got: {error}");
}

#[test]
fn rejects_xhttp_path_ss_without_leading_slash() {
    let error = Config {
        xhttp_path_ss: Some("ss".into()),
        ..base_config()
    }
    .validate()
    .unwrap_err()
    .to_string();
    assert!(error.contains("xhttp_path_ss must start with '/'"), "got: {error}");
}

#[test]
fn rejects_xhttp_path_ss_without_password_user() {
    // A vless-only user (no password) cannot back an SS-over-XHTTP path.
    let mut cfg = base_config();
    cfg.h3_alpn.push(crate::config::H3Alpn::Vless);
    cfg.users[0].password = None;
    cfg.users[0].vless_id = Some("00000000-0000-0000-0000-000000000001".into());
    cfg.xhttp_path_ss = Some("/ss".into());
    let error = cfg.validate().unwrap_err().to_string();
    assert!(error.contains("xhttp_path_ss requires"), "got: {error}");
}

#[test]
fn rejects_xhttp_path_ss_equal_to_xhttp_path_vless() {
    // One base path serves one protocol — a shared base is rejected.
    let mut cfg = base_config();
    cfg.xhttp_path_vless = Some("/x".into());
    cfg.xhttp_path_ss = Some("/x".into());
    cfg.users[0].vless_id = Some("00000000-0000-0000-0000-000000000001".into());
    let error = cfg.validate().unwrap_err().to_string();
    assert!(error.contains("ss-xhttp"), "got: {error}");
}

#[test]
fn accepts_xhttp_path_ss_udp_with_password_user() {
    Config {
        xhttp_path_ss_udp: Some("/ssu".into()),
        ..base_config()
    }
    .validate()
    .unwrap();
}

// Note: `xhttp_path_ss == xhttp_path_ss_udp` used to be rejected, but now
// opts the base path into combined mode — see `accepts_combined_xhttp_ss_path`.

#[test]
fn allows_vless_reverse_user_without_ws_path() {
    use super::super::resolved::ReverseTunnelConfig;
    use super::super::{ReverseProtocol, ReverseTunnelEndpoint};
    // A reverse-only server carrying VLESS: vless_id user with no ws/xhttp
    // path, transport provided by a protocol = "vless" reverse endpoint.
    let endpoint = ReverseTunnelEndpoint {
        addr: "ws.example.com:8443".into(),
        server_name: "reverse".into(),
        server_cert_pin: "aa".repeat(32),
        client_cert_path: "/etc/ss-client.crt".into(),
        client_key_path: "/etc/ss-client.key".into(),
        protocol: ReverseProtocol::Vless,
        mtu: true,
        backoff_min: std::time::Duration::from_secs(1),
        backoff_max: std::time::Duration::from_secs(60),
    };
    Config {
        ws_path_vless: None,
        users: vec![super::super::UserEntry {
            id: "rev-vless".into(),
            password: None,
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            ws_path_vless: None,
            xhttp_path_vless: None,
            xhttp_path_ss: None,
            xhttp_path_ss_udp: None,
            enabled: None,
        }],
        reverse_tunnel: Some(ReverseTunnelConfig { endpoints: vec![endpoint] }),
        ..base_config()
    }
    .validate()
    .unwrap();
}

#[test]
fn allows_vless_only_users() {
    Config {
        ws_path_vless: Some("/vless".into()),
        xhttp_path_vless: None,
        xhttp_path_ss: None,
        xhttp_path_ss_udp: None,
        users: vec![super::super::UserEntry {
            id: "550e8400-e29b-41d4-a716-446655440000".into(),
            password: None,
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            ws_path_vless: None,
            xhttp_path_vless: None,
            xhttp_path_ss: None,
            xhttp_path_ss_udp: None,
            enabled: None,
        }],
        ..base_config()
    }
    .validate()
    .unwrap();
}

#[test]
fn rejects_vless_path_conflict_with_tcp_path() {
    let error = Config {
        ws_path_vless: Some("/tcp".into()),
        xhttp_path_vless: None,
        xhttp_path_ss: None,
        xhttp_path_ss_udp: None,
        users: vec![
            super::super::UserEntry {
                id: "alice".into(),
                password: Some("secret".into()),
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                ws_path_vless: None,
                xhttp_path_vless: None,
                xhttp_path_ss: None,
                xhttp_path_ss_udp: None,
                enabled: None,
            },
            super::super::UserEntry {
                id: "550e8400-e29b-41d4-a716-446655440000".into(),
                password: None,
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
                ws_path_vless: None,
                xhttp_path_vless: None,
                xhttp_path_ss: None,
                xhttp_path_ss_udp: None,
                enabled: None,
            },
        ],
        ..base_config()
    }
    .validate()
    .unwrap_err()
    .to_string();

    assert!(error.contains("tcp and vless websocket paths must be distinct"));
}

#[test]
fn allows_per_user_vless_path_without_global_default() {
    Config {
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_ss: None,
        xhttp_path_ss_udp: None,
        users: vec![super::super::UserEntry {
            id: "alice".into(),
            password: None,
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            ws_path_vless: Some("/alice-vless".into()),
            xhttp_path_vless: None,
            xhttp_path_ss: None,
            xhttp_path_ss_udp: None,
            enabled: None,
        }],
        ..base_config()
    }
    .validate()
    .unwrap();
}

#[test]
fn allows_vless_id_without_path_when_raw_quic_alpn_enabled() {
    Config {
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_ss: None,
        xhttp_path_ss_udp: None,
        h3_alpn: vec![crate::config::H3Alpn::H3, crate::config::H3Alpn::Vless],
        users: vec![super::super::UserEntry {
            id: "alice".into(),
            password: None,
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            ws_path_vless: None,
            xhttp_path_vless: None,
            xhttp_path_ss: None,
            xhttp_path_ss_udp: None,
            enabled: None,
        }],
        ..base_config()
    }
    .validate()
    .unwrap();
}

#[test]
fn rejects_vless_id_without_any_path() {
    let error = Config {
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_ss: None,
        xhttp_path_ss_udp: None,
        users: vec![super::super::UserEntry {
            id: "alice".into(),
            password: None,
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            ws_path_vless: None,
            xhttp_path_vless: None,
            xhttp_path_ss: None,
            xhttp_path_ss_udp: None,
            enabled: None,
        }],
        ..base_config()
    }
    .validate()
    .unwrap_err()
    .to_string();

    assert!(
        error.contains("user alice vless_id requires at least one transport"),
        "unexpected error: {error}"
    );
}

#[test]
fn tuning_rejects_stream_window_above_connection_window() {
    let mut tuning = super::super::TuningProfile::LARGE;
    tuning.h3_stream_window_bytes = tuning.h3_connection_window_bytes + 1;
    let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
    assert!(error.contains("h3_stream_window_bytes"));
    assert!(error.contains("must not exceed"));
}

#[test]
fn tuning_rejects_zero_values() {
    let mut tuning = super::super::TuningProfile::LARGE;
    tuning.h3_udp_socket_buffer_bytes = 0;
    let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
    assert!(error.contains("h3_udp_socket_buffer_bytes"));
}

#[test]
fn tuning_rejects_oversized_h3_windows() {
    let mut tuning = super::super::TuningProfile::LARGE;
    tuning.h3_connection_window_bytes = (u32::MAX as u64) + 1;
    let error = Config { tuning, ..base_config() }.validate().unwrap_err().to_string();
    assert!(error.contains("h3_connection_window_bytes"));
}

#[test]
fn rejects_http_root_realm_with_control_characters() {
    let error = Config {
        http_root_auth: true,
        http_root_realm: "bad\nrealm".into(),
        ..base_config()
    }
    .validate()
    .unwrap_err()
    .to_string();

    assert!(error.contains("http_root_realm must not contain control characters"));
}
