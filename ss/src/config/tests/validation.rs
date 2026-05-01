use super::super::{CipherKind, Config, default_http_root_realm};

fn base_config() -> Config {
    Config {
        config_path: None,
        control: None,
        dashboard: None,
        listen: Some("127.0.0.1:3000".parse().unwrap()),
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
        ws_path_vless: None,
        xhttp_path_vless: None,
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
            enabled: None,
        }],
        method: CipherKind::Chacha20IetfPoly1305,
        access_key: Default::default(),
        tuning: super::super::TuningProfile::LARGE,
        session_resumption: Default::default(),
        http_fallback: None,
        sni_fallback: None,
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
fn allows_vless_only_users() {
    Config {
        ws_path_vless: Some("/vless".into()),
        xhttp_path_vless: None,
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
