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
        h3_initial_mtu: None,
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
        tuning: Default::default(),
        session_resumption: Default::default(),
        padding: Default::default(),
        http_fallback: None,
        sni_fallback: None,
        cluster: None,
        config_path: None,
        control: None,
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

/// Every `outcome` an edge records for a relay it tried to open
/// (`mesh_relay::open_edge_relay`).
const MESH_OPEN_OUTCOMES: &[&str] = &["fail", "ok", "refused"];

/// Every `reason` a home records for a relay stream it refused
/// (`mesh_relay::serve_relayed` and the accept loop above it).
const MESH_REJECTION_REASONS: &[&str] = &[
    "bad_setup",
    "capacity",
    "framing_mismatch",
    "no_session",
    "park_identity",
    "park_incomplete",
    "park_shape",
    "protocol_mismatch",
    "unknown_user",
];

/// Every `(outcome, close)` pair a home records for a relay stream that reached
/// the handler. Not the full product: a `miss` and an `error` never spliced, so
/// neither ever carries a close intent.
const MESH_RELAY_OUTCOMES: &[(&str, &str)] = &[
    ("error", "none"),
    ("hit", "carrier_ended"),
    ("hit", "client_done"),
    ("hit", "none"),
    ("miss", "none"),
    ("unusable", "none"),
];

/// The `# HELP` line the exporter renders for `metric`.
fn help_line(rendered: &str, metric: &str) -> String {
    let prefix = format!("# HELP {metric} ");
    rendered
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| {
            panic!("{metric} renders no HELP line — it is not described:\n{rendered}")
        })
        .to_owned()
}

/// The label values a HELP string documents, recognised by the `value = meaning`
/// shape every mesh description uses. Lets a test assert the description and the
/// emitters agree in *both* directions — an undescribed label value reaches an
/// operator as a bare string, and a described one nothing emits (as `no_route`
/// was after the home stopped resolving routes) sends them looking for a series
/// that will never appear.
fn documented_label_values(help: &str) -> std::collections::BTreeSet<String> {
    help.match_indices(" = ")
        .filter_map(|(idx, _)| help[..idx].split_whitespace().next_back())
        .map(|token| token.trim_start_matches(['(', '"']).to_owned())
        .filter(|token| {
            !token.is_empty() && token.chars().all(|c| c.is_ascii_lowercase() || c == '_')
        })
        .collect()
}

#[test]
fn mesh_relay_open_outcomes_are_described_exactly() {
    let metrics = Metrics::new(&test_config());
    for outcome in MESH_OPEN_OUTCOMES {
        metrics.record_mesh_relay_opened(outcome);
    }

    let rendered = metrics.render_prometheus();
    let help = help_line(&rendered, "outline_ss_mesh_relay_opened_total");
    for outcome in MESH_OPEN_OUTCOMES {
        assert!(
            rendered
                .contains(&format!("outline_ss_mesh_relay_opened_total{{outcome=\"{outcome}\"}}")),
            "outcome={outcome} must render:\n{rendered}",
        );
    }
    assert_eq!(
        documented_label_values(&help),
        MESH_OPEN_OUTCOMES.iter().map(|v| (*v).to_owned()).collect(),
        "the HELP text must describe exactly the outcomes the edge emits:\n{help}",
    );
}

#[test]
fn mesh_rejection_reasons_are_described_exactly() {
    let metrics = Metrics::new(&test_config());
    for reason in MESH_REJECTION_REASONS {
        metrics.record_mesh_relay_rejected(reason);
    }

    let rendered = metrics.render_prometheus();
    for reason in MESH_REJECTION_REASONS {
        assert!(
            rendered.contains(&format!(
                "outline_ss_mesh_relay_rejected_total{{reason=\"{reason}\"}} 1"
            )),
            "reason={reason} must render:\n{rendered}",
        );
    }
    // The route lookup this reason reported is gone with the home-side
    // decryption, so nothing emits it and nothing may document it.
    assert!(
        !rendered.contains(r#"reason="no_route""#),
        "no_route was retired with the home's route lookup:\n{rendered}",
    );

    let help = help_line(&rendered, "outline_ss_mesh_relay_rejected_total");
    assert_eq!(
        documented_label_values(&help),
        MESH_REJECTION_REASONS.iter().map(|v| (*v).to_owned()).collect(),
        "the HELP text must describe exactly the reasons the home emits:\n{help}",
    );
}

#[test]
fn mesh_relay_outcome_is_observable_and_described_exactly() {
    // A never-working relay went unnoticed in production because success was
    // only inferrable from byte counters. Make it a first-class signal.
    let metrics = Metrics::new(&test_config());
    for (outcome, close) in MESH_RELAY_OUTCOMES {
        metrics.record_mesh_relay_outcome(outcome, close);
    }

    let rendered = metrics.render_prometheus();
    for (outcome, close) in MESH_RELAY_OUTCOMES {
        assert!(
            rendered.contains(&format!(
                "outline_ss_mesh_relay_outcome_total{{outcome=\"{outcome}\",close=\"{close}\"}} 1"
            )),
            "outcome={outcome} close={close} must render:\n{rendered}",
        );
    }

    let help = help_line(&rendered, "outline_ss_mesh_relay_outcome_total");
    let mut expected: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (outcome, close) in MESH_RELAY_OUTCOMES {
        expected.insert((*outcome).to_owned());
        expected.insert((*close).to_owned());
    }
    assert_eq!(
        documented_label_values(&help),
        expected,
        "the HELP text must describe exactly the outcomes and closes the home emits:\n{help}",
    );
    // The reconciliation an operator is told to run: an outcome is recorded when
    // the splice *ends*, so relays still running are only on the gauge.
    assert!(
        help.contains("sum(outcome_total) + outline_ss_mesh_relay_active"),
        "the HELP must keep stating how the served total reconciles:\n{help}",
    );
}

#[test]
fn mesh_relay_label_cardinality_stays_bounded() {
    // The label sets are closed by construction (`&'static str` at every call
    // site). Pin the products anyway: a mesh label fed from a peer-supplied
    // string would be an unbounded series, and the mesh is the one path where
    // label values cross a node boundary.
    let metrics = Metrics::new(&test_config());
    for outcome in MESH_OPEN_OUTCOMES {
        metrics.record_mesh_relay_opened(outcome);
    }
    for reason in MESH_REJECTION_REASONS {
        metrics.record_mesh_relay_rejected(reason);
    }
    for (outcome, close) in MESH_RELAY_OUTCOMES {
        metrics.record_mesh_relay_outcome(outcome, close);
    }
    for role in ["edge", "home"] {
        for direction in ["up", "down"] {
            for transport in ["tcp", "udp"] {
                metrics.mesh_bytes_counter(role, direction, transport).increment(1);
            }
            metrics.mesh_datagrams_counter(role, direction).increment(1);
        }
    }

    let rendered = metrics.render_prometheus();
    let series = |metric: &str| {
        rendered
            .lines()
            .filter(|line| line.starts_with(&format!("{metric}{{")))
            .count()
    };
    assert_eq!(series("outline_ss_mesh_relay_opened_total"), MESH_OPEN_OUTCOMES.len());
    assert_eq!(series("outline_ss_mesh_relay_rejected_total"), MESH_REJECTION_REASONS.len());
    assert_eq!(series("outline_ss_mesh_relay_outcome_total"), MESH_RELAY_OUTCOMES.len());
    assert_eq!(series("outline_ss_mesh_bytes_total"), 8);
    assert_eq!(series("outline_ss_mesh_datagrams_total"), 4);
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
}

#[test]
fn tcp_handshake_replay_metrics_render_with_labels() {
    let metrics = Metrics::new(&test_config());
    metrics.record_tcp_handshake_replay_dropped("alice", Protocol::Http1);
    metrics.record_tcp_handshake_replay_dropped("alice", Protocol::Http1);
    metrics.record_tcp_handshake_replay_store_full("bob", Protocol::Http1);

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains(
        "outline_ss_tcp_handshake_replay_dropped_total{user=\"alice\",protocol=\"http1\",app_protocol=\"shadowsocks\"} 2"
    ));
    assert!(rendered.contains(
        "outline_ss_tcp_handshake_replay_store_full_total{user=\"bob\",protocol=\"http1\",app_protocol=\"shadowsocks\"} 1"
    ));
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
    metrics.record_orphan_downlink_replay_truncated("tcp", "evicted");
    metrics.record_orphan_downlink_replay_truncated("tcp", "evicted");
    metrics.set_orphan_downlink_buf_bytes(8192.0);

    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("outline_ss_orphan_downlink_replay_bytes_total{transport=\"tcp\"} 4000"),
        "replay bytes counter missing or wrong value:\n{rendered}",
    );
    assert!(
        rendered.contains(
            "outline_ss_orphan_downlink_replay_truncated_total{transport=\"tcp\",reason=\"evicted\"} 2"
        ),
        "truncated counter missing or wrong value (it carries a `reason` label so \
         \"the ring is absent\" and \"the ring is too small\" stay apart):\n{rendered}",
    );
    assert!(
        rendered.contains("outline_ss_orphan_downlink_buf_bytes 8192"),
        "buf-bytes gauge missing or wrong value:\n{rendered}",
    );
}
