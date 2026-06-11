use std::sync::Arc;

use crate::config::Config;

use super::{AppProtocol, DisconnectReason, Metrics, Protocol, Transport};

fn test_config() -> Config {
    Config {
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
        metrics_listen: Some("127.0.0.1:9090".parse().unwrap()),
        metrics_path: "/metrics".to_owned(),
        prefer_ipv4_upstream: false,
        outbound_ipv6_prefix: None,
        outbound_ipv6_interface: None,
        outbound_ipv6_refresh_secs: 30,
        outbound_ipv6_sticky: false,
        outbound_ipv6_sticky_ttl_secs: 1800,
        ws_path_tcp: "/tcp".to_owned(),
        ws_path_udp: "/udp".to_owned(),
        ws_path_vless: None,
        xhttp_path_vless: None,
        http_root_auth: false,
        http_root_realm: "Authorization required".to_owned(),
        users: vec![crate::config::UserEntry {
            id: "default".to_owned(),
            password: Some("secret".to_owned()),
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
            vless_id: None,
            ws_path_vless: None,
            xhttp_path_vless: None,
            enabled: None,
        }],
        method: crate::config::CipherKind::Chacha20IetfPoly1305,
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

#[test]
fn renders_prometheus_metrics() {
    let metrics = Metrics::new(&test_config());
    let session =
        metrics.open_websocket_session(Transport::Tcp, Protocol::Http2, AppProtocol::Shadowsocks);
    metrics.record_websocket_binary_frame(
        Transport::Tcp,
        Protocol::Http2,
        AppProtocol::Shadowsocks,
        "in",
        123,
    );
    metrics.record_pong_deadline_disconnect(Transport::Tcp, AppProtocol::Shadowsocks);
    metrics.observe_ws_data_channel_fill(Transport::Tcp, AppProtocol::Shadowsocks, 7);
    metrics.record_tcp_authenticated_session("default", Protocol::Http2, AppProtocol::Shadowsocks);
    metrics.record_tcp_connect(
        "default",
        Protocol::Http2,
        AppProtocol::Shadowsocks,
        "success",
        0.015,
    );
    metrics.record_udp_relay_drop(
        Transport::Udp,
        Protocol::Http2,
        AppProtocol::Shadowsocks,
        "concurrency_limit",
    );
    metrics.record_client_session(
        "default",
        Protocol::Http2,
        Transport::Udp,
        AppProtocol::Shadowsocks,
    );
    session.finish(DisconnectReason::Normal);

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("outline_ss_websocket_upgrades_total"));
    assert!(rendered.contains("app_protocol=\"shadowsocks\""));
    assert!(rendered.contains("outline_ss_websocket_frame_size_bytes_bucket"));
    assert!(rendered.contains("outline_ss_websocket_pong_deadline_total"));
    assert!(rendered.contains("outline_ss_ws_data_channel_fill_bucket"));
    assert!(rendered.contains("outline_ss_build_info"));
    assert!(rendered.contains("user=\"default\",protocol=\"http2\""));
    assert!(rendered.contains("outline_ss_tcp_upstream_connect_duration_seconds_bucket"));
    assert!(rendered.contains("outline_ss_client_sessions_total"));
    assert!(rendered.contains("outline_ss_client_last_seen_seconds"));
    assert!(rendered.contains("outline_ss_client_active"));
    assert!(rendered.contains("outline_ss_client_up"));
    assert!(rendered.contains("outline_ss_udp_relay_drops_total"));
    assert!(rendered.contains(
        "outline_ss_udp_relay_drops_total{transport=\"udp\",protocol=\"http2\",app_protocol=\"shadowsocks\",reason=\"concurrency_limit\"} 1"
    ));
    #[cfg(target_os = "linux")]
    assert!(rendered.contains("outline_ss_process_resident_memory_bytes"));
    #[cfg(target_os = "linux")]
    assert!(rendered.contains("outline_ss_process_threads"));
    #[cfg(target_os = "linux")]
    assert!(rendered.contains("outline_ss_process_virtual_anon_private_bytes"));
    #[cfg(target_os = "linux")]
    assert!(rendered.contains("outline_ss_process_virtual_file_private_bytes"));
    #[cfg(target_os = "linux")]
    assert!(rendered.contains("outline_ss_process_virtual_top_mapping_size_bytes"));
    #[cfg(target_os = "linux")]
    assert!(rendered.contains("outline_ss_process_virtual_top_mapping_gap_bytes"));
}

#[test]
fn user_counters_cache_returns_same_handles() {
    let metrics = Metrics::new(&test_config());
    let user: Arc<str> = Arc::from("default");
    let first = metrics.user_counters(&user);
    let second = metrics.user_counters(&user);
    assert!(Arc::ptr_eq(&first, &second), "cache must return the same Arc");
}

#[test]
fn no_cert_chain_metric_records_sni_label() {
    let metrics = Metrics::new(&test_config());
    metrics.record_tls_handshake_no_cert_chain(Some("foo.example"));
    metrics.record_tls_handshake_no_cert_chain(Some("FOO.example")); // case-insensitive
    metrics.record_tls_handshake_no_cert_chain(Some("bar.example"));
    metrics.record_tls_handshake_no_cert_chain(None);

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("outline_ss_tls_handshake_no_cert_chain_total{sni=\"foo.example\"} 2")
    );
    assert!(
        rendered.contains("outline_ss_tls_handshake_no_cert_chain_total{sni=\"bar.example\"} 1")
    );
    assert!(rendered.contains("outline_ss_tls_handshake_no_cert_chain_total{sni=\"<none>\"} 1"));
}

#[test]
fn no_cert_chain_metric_sanitizes_invalid_input() {
    let metrics = Metrics::new(&test_config());
    metrics.record_tls_handshake_no_cert_chain(Some("evil\nname")); // control byte
    metrics.record_tls_handshake_no_cert_chain(Some(&"a".repeat(300))); // too long

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("outline_ss_tls_handshake_no_cert_chain_total{sni=\"<invalid>\"} 1"));
    assert!(rendered.contains("outline_ss_tls_handshake_no_cert_chain_total{sni=\"<long>\"} 1"));
}

#[test]
fn no_cert_chain_metric_caps_cardinality() {
    let metrics = Metrics::new(&test_config());
    // Generate well past the cap. Numerical SNIs differ on every
    // record so each one tries to claim a fresh label.
    for i in 0..200 {
        metrics.record_tls_handshake_no_cert_chain(Some(&format!("scan-{i:03}.example")));
    }
    let rendered = metrics.render_prometheus();
    // The overflow bucket must be present, and the number of distinct
    // SNI labels must not exceed the cap by more than the racy slack.
    assert!(rendered.contains("outline_ss_tls_handshake_no_cert_chain_total{sni=\"<overflow>\"}"));
    let distinct_snis = rendered
        .lines()
        .filter(|l| l.starts_with("outline_ss_tls_handshake_no_cert_chain_total{sni="))
        .count();
    // Cap is 64; allow a small margin for the racy size check.
    assert!(
        distinct_snis <= 70,
        "cardinality cap not respected: {distinct_snis} distinct SNI labels"
    );
}

#[test]
fn user_counters_increments_visible_in_render() {
    let metrics = Metrics::new(&test_config());
    let user: Arc<str> = Arc::from("alice");
    metrics.record_client_session(
        Arc::clone(&user),
        Protocol::Http3,
        Transport::Tcp,
        AppProtocol::Vless,
    );
    let counters = metrics.user_counters(&user);
    counters.tcp_in(AppProtocol::Vless, Protocol::Http3).increment(100);
    counters.tcp_out(AppProtocol::Vless, Protocol::Http3).increment(250);
    counters
        .udp_out(AppProtocol::Shadowsocks, Protocol::Http3)
        .increment(64);

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains(
        "outline_ss_tcp_payload_bytes_total{user=\"alice\",app_protocol=\"vless\",protocol=\"http3\",direction=\"client_to_target\"} 100"
    ));
    assert!(rendered.contains(
        "outline_ss_tcp_payload_bytes_total{user=\"alice\",app_protocol=\"vless\",protocol=\"http3\",direction=\"target_to_client\"} 250"
    ));
    assert!(rendered.contains(
        "outline_ss_udp_payload_bytes_total{user=\"alice\",app_protocol=\"shadowsocks\",protocol=\"http3\",direction=\"target_to_client\"} 64"
    ));
}

#[test]
fn orphan_downlink_v2_metrics_render() {
    let metrics = Metrics::new(&test_config());

    metrics.record_orphan_downlink_replay_bytes("tcp", 0);
    metrics.record_orphan_downlink_replay_bytes("tcp", 1500);
    metrics.record_orphan_downlink_replay_bytes("tcp", 2500);
    metrics.record_orphan_downlink_replay_truncated("tcp");
    metrics.record_orphan_downlink_replay_truncated("tcp");
    metrics.set_orphan_downlink_buf_bytes(8192.0);

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("outline_ss_orphan_downlink_replay_bytes_total{transport=\"tcp\"} 4000"),
        "replay bytes counter missing or wrong value:\n{rendered}",
    );
    assert!(
        rendered.contains("outline_ss_orphan_downlink_replay_truncated_total{transport=\"tcp\"} 2"),
        "truncated counter missing or wrong value:\n{rendered}",
    );
    assert!(
        rendered.contains("outline_ss_orphan_downlink_buf_bytes 8192"),
        "buf-bytes gauge missing or wrong value:\n{rendered}",
    );
}
