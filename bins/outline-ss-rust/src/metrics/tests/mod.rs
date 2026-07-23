use std::sync::Arc;

use crate::config::Config;

use super::{AppProtocol, DisconnectReason, Metrics, Protocol, Transport};

pub(super) fn test_config() -> Config {
    Config {
        listen: Some("127.0.0.1:3000".parse().unwrap()),
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
        outbound_ipv6_prefix_interface: None,
        outbound_ipv6_refresh_secs: 30,
        outbound_ipv6_sticky: false,
        outbound_ipv6_sticky_ttl_secs: 1800,
        ws_path_tcp: "/tcp".to_owned(),
        ws_path_udp: "/udp".to_owned(),
        ws_path_ss: None,
        ws_path_vless: None,
        xhttp_path_vless: None,
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        http_root_auth: false,
        http_root_realm: "Authorization required".to_owned(),
        users: vec![crate::config::UserEntry {
            id: "default".to_owned(),
            password: Some("secret".to_owned()),
            fwmark: None,
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
        }],
        method: crate::config::CipherKind::Chacha20IetfPoly1305,
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

#[test]
fn renders_prometheus_metrics() {
    let metrics = Metrics::new(&test_config());
    let session =
        metrics.open_websocket_session(Transport::Tcp, Protocol::Http2, AppProtocol::Shadowsocks);
    metrics.record_websocket_binary_frame(
        Transport::Tcp,
        Protocol::Http2,
        AppProtocol::Shadowsocks,
        "up",
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
    assert!(rendered.contains("outline_ss_websocket_data_channel_fill_bucket"));
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
fn websocket_binary_frame_counters_accumulate_in_render() {
    let metrics = Metrics::new(&test_config());
    // Same label combination twice: the cached counter handle must accumulate
    // rather than resolve a fresh series each call.
    metrics.record_websocket_binary_frame(
        Transport::Tcp,
        Protocol::Http2,
        AppProtocol::Shadowsocks,
        "up",
        100,
    );
    metrics.record_websocket_binary_frame(
        Transport::Tcp,
        Protocol::Http2,
        AppProtocol::Shadowsocks,
        "up",
        40,
    );
    // A different direction resolves a distinct cached cell.
    metrics.record_websocket_binary_frame(
        Transport::Tcp,
        Protocol::Http2,
        AppProtocol::Shadowsocks,
        "down",
        7,
    );

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains(
            "outline_ss_websocket_frames_total{transport=\"tcp\",protocol=\"http2\",app_protocol=\"shadowsocks\",direction=\"up\"} 2"
        ),
        "frame count for up direction wrong:\n{rendered}"
    );
    assert!(
        rendered.contains(
            "outline_ss_websocket_bytes_total{transport=\"tcp\",protocol=\"http2\",app_protocol=\"shadowsocks\",direction=\"up\"} 140"
        ),
        "byte sum for up direction wrong:\n{rendered}"
    );
    assert!(
        rendered.contains(
            "outline_ss_websocket_bytes_total{transport=\"tcp\",protocol=\"http2\",app_protocol=\"shadowsocks\",direction=\"down\"} 7"
        ),
        "byte sum for down direction wrong:\n{rendered}"
    );
    // The companion frame-size histogram still resolves per call.
    assert!(rendered.contains("outline_ss_websocket_frame_size_bytes_bucket"));
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
fn renders_mesh_relay_metrics() {
    let metrics = Metrics::new(&test_config());
    metrics.record_mesh_relay_opened("ok");
    metrics.record_mesh_relay_opened("ok");
    metrics.record_mesh_relay_opened("fail");
    let active = metrics.open_mesh_relay();

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("outline_ss_mesh_relay_opened_total{outcome=\"ok\"} 2"));
    assert!(rendered.contains("outline_ss_mesh_relay_opened_total{outcome=\"fail\"} 1"));
    assert!(
        rendered.contains("outline_ss_mesh_relay_active 1"),
        "an in-flight relay guard must show one active relay"
    );

    drop(active);
    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("outline_ss_mesh_relay_active 0"),
        "dropping the guard must return the active gauge to zero"
    );
}

#[test]
fn renders_mesh_relay_rejections() {
    let metrics = Metrics::new(&test_config());
    metrics.record_mesh_relay_rejected("capacity");
    metrics.record_mesh_relay_rejected("capacity");

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("outline_ss_mesh_relay_rejected_total{reason=\"capacity\"} 2"),
        "refused relay streams must be counted by reason:\n{rendered}",
    );
}

#[test]
fn renders_mesh_traffic_metrics() {
    let metrics = Metrics::new(&test_config());

    // Byte counters: an edge forwarding, and a home serving, the same relayed
    // session from opposite ends. Handles are pre-resolved once, then incremented.
    metrics.mesh_bytes_counter("edge", "up", "tcp").increment(1_000);
    metrics.mesh_bytes_counter("edge", "down", "tcp").increment(4_000);
    metrics.mesh_bytes_counter("home", "up", "udp").increment(500);
    let dg = metrics.mesh_datagrams_counter("edge", "up");
    dg.increment(1);
    dg.increment(1);

    // Throttle-hint accounting: edge sends, home receives (delivered/dropped),
    // and a malformed control datagram is dropped.
    metrics.record_mesh_throttle_hint_sent();
    metrics.record_mesh_throttle_hint_received("delivered");
    metrics.record_mesh_throttle_hint_received("dropped");
    metrics.record_mesh_control_datagram_error();

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains(
        "outline_ss_mesh_bytes_total{role=\"edge\",direction=\"up\",transport=\"tcp\"} 1000"
    ));
    assert!(rendered.contains(
        "outline_ss_mesh_bytes_total{role=\"edge\",direction=\"down\",transport=\"tcp\"} 4000"
    ));
    assert!(rendered.contains(
        "outline_ss_mesh_bytes_total{role=\"home\",direction=\"up\",transport=\"udp\"} 500"
    ));
    assert!(rendered.contains("outline_ss_mesh_datagrams_total{role=\"edge\",direction=\"up\"} 2"));
    assert!(rendered.contains("outline_ss_mesh_throttle_hints_sent_total 1"));
    assert!(
        rendered.contains("outline_ss_mesh_throttle_hints_received_total{outcome=\"delivered\"} 1")
    );
    assert!(
        rendered.contains("outline_ss_mesh_throttle_hints_received_total{outcome=\"dropped\"} 1")
    );
    assert!(rendered.contains("outline_ss_mesh_control_datagram_errors_total 1"));
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
        "outline_ss_tcp_payload_bytes_total{user=\"alice\",app_protocol=\"vless\",protocol=\"http3\",direction=\"up\"} 100"
    ));
    assert!(rendered.contains(
        "outline_ss_tcp_payload_bytes_total{user=\"alice\",app_protocol=\"vless\",protocol=\"http3\",direction=\"down\"} 250"
    ));
    assert!(rendered.contains(
        "outline_ss_udp_payload_bytes_total{user=\"alice\",app_protocol=\"shadowsocks\",protocol=\"http3\",direction=\"down\"} 64"
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
