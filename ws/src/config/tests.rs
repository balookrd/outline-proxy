use std::net::SocketAddr;
#[cfg(feature = "tun")]
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use outline_routing::RouteTarget;
use outline_uplink::{LoadBalancingMode, RoutingScope, UplinkTransport};
use socks5_proto::{Socks5AuthConfig, Socks5AuthUserConfig};

use super::{ConfigFile, load_config, normalize_outline_section};

#[test]
fn config_deserializes() {
    let cfg = r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        tcp_ws_mode = "h2"
        udp_ws_url = "wss://example.com/secret/udp"
        udp_ws_mode = "h2"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"
        username = "alice"
        password = "secret"
    "#;
    let parsed: ConfigFile = toml::from_str(cfg).unwrap();
    let socks5 = parsed.socks5.unwrap();
    assert_eq!(socks5.listen.unwrap(), SocketAddr::from(([127, 0, 0, 1], 1080)));
    assert_eq!(socks5.username.as_deref(), Some("alice"));
    assert_eq!(socks5.password.as_deref(), Some("secret"));
}

#[tokio::test]
async fn load_config_enables_single_optional_socks5_auth() {
    let path = std::env::temp_dir().join("outline-ws-rust-socks5-auth.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"
        username = "alice"
        password = "secret"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = load_config(&path, &args).await.unwrap();
    assert_eq!(
        config.socks5_auth,
        Some(Socks5AuthConfig {
            users: vec![Socks5AuthUserConfig {
                username: "alice".to_string(),
                password: "secret".to_string(),
            }],
        })
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_enables_multiple_socks5_users() {
    let path = std::env::temp_dir().join("outline-ws-rust-socks5-auth-users.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"

        [[socks5.users]]
        username = "alice"
        password = "secret1"

        [[socks5.users]]
        username = "bob"
        password = "secret2"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = load_config(&path, &args).await.unwrap();
    assert_eq!(
        config.socks5_auth,
        Some(Socks5AuthConfig {
            users: vec![
                Socks5AuthUserConfig {
                    username: "alice".to_string(),
                    password: "secret1".to_string(),
                },
                Socks5AuthUserConfig {
                    username: "bob".to_string(),
                    password: "secret2".to_string(),
                },
            ],
        })
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_partial_socks5_auth() {
    let path = std::env::temp_dir().join("outline-ws-rust-socks5-auth-partial.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"
        username = "alice"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    assert!(format!("{err:#}").contains("missing socks5 password"));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_mixed_single_and_multi_socks5_auth() {
    let path = std::env::temp_dir().join("outline-ws-rust-socks5-auth-mixed.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"
        username = "alice"
        password = "secret"

        [[socks5.users]]
        username = "bob"
        password = "secret2"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    assert!(format!("{err:#}").contains("not both"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn config_deserializes_multiple_uplinks() {
    let cfg = r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [probe]
        interval_secs = 15
        timeout_secs = 5
        max_concurrent = 3
        max_dials = 1

        [probe.ws]
        enabled = true

        [probe.http]
        url = "http://example.com/"

        [probe.dns]
        server = "1.1.1.1"
        port = 53
        name = "example.com"

        [load_balancing]
        mode = "active_passive"
        routing_scope = "per_uplink"
        warm_standby_tcp = 1
        warm_standby_udp = 1
        rtt_ewma_alpha = 0.4
        failure_penalty_ms = 750
        failure_penalty_max_ms = 20000
        failure_penalty_halflife_secs = 45

        [[uplinks]]
        name = "primary"
        tcp_ws_url = "wss://primary.example.com/secret/tcp"
        tcp_ws_mode = "h3"
        weight = 1.5
        fwmark = 100
        udp_ws_url = "wss://primary.example.com/secret/udp"
        udp_ws_mode = "h3"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [[uplinks]]
        name = "backup"
        tcp_ws_url = "wss://backup.example.com/secret/tcp"
        tcp_ws_mode = "h2"
        udp_ws_url = "wss://backup.example.com/secret/udp"
        udp_ws_mode = "h2"
        method = "aes-128-gcm"
        password = "Secret1"
    "#;
    let parsed: ConfigFile = toml::from_str(cfg).unwrap();
    let outline = normalize_outline_section(&parsed).unwrap();
    let uplinks = outline.uplinks.unwrap();
    assert_eq!(uplinks.len(), 2);
    assert_eq!(uplinks[0].fwmark, Some(100));
    assert_eq!(uplinks[0].weight, Some(1.5));
    let probe = outline.probe.unwrap();
    assert_eq!(probe.max_concurrent, Some(3));
    assert_eq!(probe.max_dials, Some(1));
    let lb = outline.load_balancing.unwrap();
    assert_eq!(lb.mode, Some(LoadBalancingMode::ActivePassive));
    assert_eq!(lb.routing_scope, Some(RoutingScope::PerUplink));
    assert_eq!(lb.warm_standby_tcp, Some(1));
    assert_eq!(lb.warm_standby_udp, Some(1));
    assert_eq!(lb.rtt_ewma_alpha, Some(0.4));
    assert_eq!(lb.failure_penalty_ms, Some(750));
    assert_eq!(lb.failure_penalty_max_ms, Some(20000));
    assert_eq!(lb.failure_penalty_halflife_secs, Some(45));
}

#[test]
fn config_deserializes_global_routing_scope() {
    let cfg = r#"
        [load_balancing]
        mode = "active_passive"
        routing_scope = "global"

        [[uplinks]]
        name = "primary"
        tcp_ws_url = "wss://primary.example.com/secret/tcp"
        tcp_ws_mode = "h2"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
    "#;
    let parsed: ConfigFile = toml::from_str(cfg).unwrap();
    let outline = normalize_outline_section(&parsed).unwrap();
    let lb = outline.load_balancing.unwrap();
    assert_eq!(lb.mode, Some(LoadBalancingMode::ActivePassive));
    assert_eq!(lb.routing_scope, Some(RoutingScope::Global));
}

#[cfg(feature = "tun")]
#[test]
fn config_deserializes_tun() {
    let cfg = r#"
        [tun]
        path = "/dev/net/tun"
        name = "tun0"
        mtu = 1500
        max_flows = 2048
        idle_timeout_secs = 120

        [tun.tcp]
        connect_timeout_secs = 8
        handshake_timeout_secs = 12
        half_close_timeout_secs = 45
        max_pending_server_bytes = 524288
        backlog_abort_grace_secs = 4
        backlog_hard_limit_multiplier = 3
        backlog_no_progress_abort_secs = 9
        max_buffered_client_segments = 1024
        max_buffered_client_bytes = 131072
        max_retransmits = 9
    "#;
    let parsed: ConfigFile = toml::from_str(cfg).unwrap();
    let tun = parsed.tun.unwrap();
    assert_eq!(tun.path.unwrap(), PathBuf::from("/dev/net/tun"));
    assert_eq!(tun.name.unwrap(), "tun0");
    assert_eq!(tun.mtu, Some(1500));
    assert_eq!(tun.max_flows, Some(2048));
    assert_eq!(tun.idle_timeout_secs, Some(120));
    let tcp = tun.tcp.unwrap();
    assert_eq!(tcp.connect_timeout_secs, Some(8));
    assert_eq!(tcp.handshake_timeout_secs, Some(12));
    assert_eq!(tcp.half_close_timeout_secs, Some(45));
    assert_eq!(tcp.max_pending_server_bytes, Some(524288));
    assert_eq!(tcp.backlog_abort_grace_secs, Some(4));
    assert_eq!(tcp.backlog_hard_limit_multiplier, Some(3));
    assert_eq!(tcp.backlog_no_progress_abort_secs, Some(9));
    assert_eq!(tcp.max_buffered_client_segments, Some(1024));
    assert_eq!(tcp.max_buffered_client_bytes, Some(131072));
    assert_eq!(tcp.max_retransmits, Some(9));
}

#[tokio::test]
async fn load_config_disables_probes_when_not_configured() {
    let path = std::env::temp_dir().join("outline-ws-rust-no-probe.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        tcp_ws_mode = "h2"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = super::load_config(&path, &args).await.unwrap();
    assert!(!config.groups[0].probe.enabled());

    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "tun")]
#[tokio::test]
async fn load_config_enables_tun_when_configured() {
    let path = std::env::temp_dir().join("outline-ws-rust-tun.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [tun]
        path = "/dev/tun0"
        mtu = 1500
        max_flows = 512
        idle_timeout_secs = 60

        [tun.tcp]
        connect_timeout_secs = 7
        handshake_timeout_secs = 9
        half_close_timeout_secs = 30
        max_pending_server_bytes = 262144
        backlog_abort_grace_secs = 5
        backlog_hard_limit_multiplier = 4
        backlog_no_progress_abort_secs = 11
        max_buffered_client_segments = 2048
        max_buffered_client_bytes = 65536
        max_retransmits = 6
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = load_config(&path, &args).await.unwrap();
    assert_eq!(config.tun.as_ref().unwrap().path, PathBuf::from("/dev/tun0"));
    assert_eq!(config.tun.as_ref().unwrap().mtu, 1500);
    assert_eq!(config.tun.as_ref().unwrap().max_flows, 512);
    assert_eq!(config.tun.as_ref().unwrap().idle_timeout, Duration::from_secs(60));
    assert_eq!(config.tun.as_ref().unwrap().tcp.connect_timeout, Duration::from_secs(7));
    assert_eq!(config.tun.as_ref().unwrap().tcp.handshake_timeout, Duration::from_secs(9));
    assert_eq!(config.tun.as_ref().unwrap().tcp.half_close_timeout, Duration::from_secs(30));
    assert_eq!(config.tun.as_ref().unwrap().tcp.max_pending_server_bytes, 262_144);
    assert_eq!(config.tun.as_ref().unwrap().tcp.backlog_abort_grace, Duration::from_secs(5));
    assert_eq!(config.tun.as_ref().unwrap().tcp.backlog_hard_limit_multiplier, 4);
    assert_eq!(
        config.tun.as_ref().unwrap().tcp.backlog_no_progress_abort,
        Duration::from_secs(11)
    );
    assert_eq!(config.tun.as_ref().unwrap().tcp.max_buffered_client_segments, 2048);
    assert_eq!(config.tun.as_ref().unwrap().tcp.max_buffered_client_bytes, 65_536);
    assert_eq!(config.tun.as_ref().unwrap().tcp.max_retransmits, 6);
}

#[cfg(feature = "tun")]
#[tokio::test]
async fn load_config_enables_tun_from_cli_without_tun_section() {
    let path = std::env::temp_dir().join("outline-ws-rust-no-tun-section.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from([
        "test",
        "--tun-path",
        "/dev/net/tun",
        "--tun-name",
        "tun0",
        "--tun-mtu",
        "1500",
    ]);
    let config = load_config(&path, &args).await.unwrap();
    assert_eq!(config.tun.as_ref().unwrap().path, PathBuf::from("/dev/net/tun"));
    assert_eq!(config.tun.as_ref().unwrap().name.as_deref(), Some("tun0"));
    assert_eq!(config.tun.as_ref().unwrap().mtu, 1500);

    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn load_config_enables_metrics_from_cli_without_metrics_section() {
    let path = std::env::temp_dir().join("outline-ws-rust-no-metrics-section.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from([
        "test",
        "--metrics-listen",
        "[::1]:9090",
        "--listen",
        "127.0.0.1:1080",
    ]);
    let config = load_config(&path, &args).await.unwrap();
    assert_eq!(config.metrics.as_ref().unwrap().listen, "[::1]:9090".parse().unwrap());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_disables_probes_when_probe_section_has_no_checks() {
    let path = std::env::temp_dir().join("outline-ws-rust-empty-probe.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        tcp_ws_mode = "h2"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"

        [probe]
        interval_secs = 15
        timeout_secs = 5
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = super::load_config(&path, &args).await.unwrap();
    assert!(!config.groups[0].probe.enabled());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_supports_direct_shadowsocks_uplink() {
    let path = std::env::temp_dir().join("outline-ws-rust-direct-ss.toml");
    std::fs::write(
        &path,
        r#"
        transport = "shadowsocks"
        tcp_addr = "ss.example.com:8388"
        udp_addr = "ss.example.com:8388"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = super::load_config(&path, &args).await.unwrap();
    assert_eq!(config.groups.len(), 1);
    assert_eq!(config.groups[0].uplinks.len(), 1);
    let uplink = &config.groups[0].uplinks[0];
    assert_eq!(uplink.transport, UplinkTransport::Shadowsocks);
    assert_eq!(uplink.tcp_addr.as_ref().unwrap().to_string(), "ss.example.com:8388");
    assert_eq!(uplink.udp_addr.as_ref().unwrap().to_string(), "ss.example.com:8388");
    assert!(uplink.tcp_ws_url.is_none());
    assert!(uplink.udp_ws_url.is_none());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_missing_all_ingress() {
    let path = std::env::temp_dir().join("outline-ws-rust-no-ingress.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = super::load_config(&path, &args).await.unwrap_err();
    assert!(format!("{err:#}").contains("no ingress configured"));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_new_shape_groups_and_routes() {
    let path = std::env::temp_dir().join("outline-ws-rust-groups-routes.toml");
    std::fs::write(
        &path,
        r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [probe]
        interval_secs = 120

        [probe.http]
        url = "http://example.com/"

        [[uplink_group]]
        name = "main"
        mode = "active_active"
        routing_scope = "per_flow"

        [[uplink_group]]
        name = "backup"
        mode = "active_passive"
        routing_scope = "global"

        [uplink_group.probe]
        interval_secs = 60

        [[uplinks]]
        name = "primary"
        group = "main"
        tcp_ws_url = "wss://main.example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [[uplinks]]
        name = "edge"
        group = "backup"
        tcp_ws_url = "wss://backup.example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [[route]]
        prefixes = ["10.0.0.0/8", "192.168.0.0/16", "fc00::/7"]
        via = "direct"

        [[route]]
        prefixes = ["1.1.1.1/32"]
        via = "main"
        fallback_via = "backup"

        [[route]]
        default = true
        via = "main"
        fallback_direct = true
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = super::load_config(&path, &args).await.unwrap();

    // Groups parsed with per-group LB + merged probe.
    assert_eq!(config.groups.len(), 2);
    assert_eq!(config.groups[0].name, "main");
    assert_eq!(config.groups[0].uplinks.len(), 1);
    assert_eq!(config.groups[0].load_balancing.mode, LoadBalancingMode::ActiveActive);
    assert_eq!(config.groups[0].load_balancing.routing_scope, RoutingScope::PerFlow);
    // Group "main" has no probe override → inherits template interval (120 s).
    assert_eq!(config.groups[0].probe.interval, Duration::from_secs(120));

    assert_eq!(config.groups[1].name, "backup");
    assert_eq!(config.groups[1].load_balancing.mode, LoadBalancingMode::ActivePassive);
    assert_eq!(config.groups[1].load_balancing.routing_scope, RoutingScope::Global);
    // Group "backup" overrides interval (60 s) but inherits http probe from template.
    assert_eq!(config.groups[1].probe.interval, Duration::from_secs(60));
    assert!(config.groups[1].probe.http.is_some());

    // Routing table: 2 rules + 1 default, `direct` + group + fallback parsed.
    let routing = config.routing.as_ref().expect("routing table must be built");
    assert_eq!(routing.rules.len(), 2);
    assert_eq!(routing.rules[0].target, RouteTarget::Direct);
    assert_eq!(routing.rules[0].fallback, None);
    assert_eq!(routing.rules[1].target, RouteTarget::Group("main".to_string()));
    assert_eq!(routing.rules[1].fallback, Some(RouteTarget::Group("backup".to_string())));
    assert_eq!(routing.default_target, RouteTarget::Group("main".to_string()));
    assert_eq!(routing.default_fallback, Some(RouteTarget::Direct));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_unknown_group_in_route() {
    let path = std::env::temp_dir().join("outline-ws-rust-route-unknown-group.toml");
    std::fs::write(
        &path,
        r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"

        [[uplinks]]
        name = "primary"
        group = "main"
        tcp_ws_url = "wss://main.example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [[route]]
        default = true
        via = "nonexistent"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = super::load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("nonexistent"), "got: {msg}");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_too_many_uplink_groups() {
    let path = std::env::temp_dir().join("outline-ws-rust-too-many-groups.toml");
    let mut body = String::from("[socks5]\nlisten = \"127.0.0.1:1080\"\n\n");
    // 65 groups — one above the 64-group cap.
    for i in 0..65 {
        body.push_str(&format!("[[uplink_group]]\nname = \"g{i}\"\n\n"));
        body.push_str(&format!(
            "[[uplinks]]\nname = \"u{i}\"\ngroup = \"g{i}\"\n\
             tcp_ws_url = \"wss://e.example.com/secret/tcp\"\n\
             method = \"chacha20-ietf-poly1305\"\npassword = \"Secret0\"\n\n"
        ));
    }
    std::fs::write(&path, body).unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = super::load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("too many") && msg.contains("64"), "got: {msg}");

    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "tun")]
#[tokio::test]
async fn load_config_allows_tun_without_socks5_listener() {
    let path = std::env::temp_dir().join("outline-ws-rust-tun-only.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [tun]
        path = "/dev/tun0"
        mtu = 1500
        max_flows = 512
        idle_timeout_secs = 60

        [tun.tcp]
        connect_timeout_secs = 7
        handshake_timeout_secs = 9
        half_close_timeout_secs = 30
        max_pending_server_bytes = 262144
        max_buffered_client_segments = 2048
        max_buffered_client_bytes = 65536
        max_retransmits = 6
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = super::load_config(&path, &args).await.unwrap();
    assert!(config.listen.is_none());
    assert!(config.tun.is_some());

    let _ = std::fs::remove_file(path);
}

// ── Edge-case validation tests ───────────────────────────────────────────────

#[tokio::test]
async fn load_config_rejects_invalid_yaml() {
    let path = std::env::temp_dir().join("outline-ws-rust-invalid.yaml");
    std::fs::write(
        &path,
        // Invalid YAML: unterminated mapping with bad indentation.
        "socks5:\n  listen: [unterminated\n",
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("failed to parse"), "got: {msg}");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_uplink_group_without_uplinks() {
    let path = std::env::temp_dir().join("outline-ws-rust-group-no-uplinks.toml");
    std::fs::write(
        &path,
        r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("no [[uplinks]]") || msg.contains("no uplinks"),
        "got: {msg}"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_route_without_prefixes_or_file() {
    let path = std::env::temp_dir().join("outline-ws-rust-route-empty-rule.toml");
    std::fs::write(
        &path,
        r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"

        [[uplinks]]
        name = "primary"
        group = "main"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [[route]]
        default = true
        via = "main"

        [[route]]
        via = "main"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("prefixes") && msg.contains("file"),
        "got: {msg}"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_empty_route_section() {
    let path = std::env::temp_dir().join("outline-ws-rust-route-empty-arr.yaml");
    // YAML explicit empty array: simulate `route = []` via empty list.
    // TOML doesn't allow literal empty `[[route]]` without entries, so use
    // YAML where the user can type `route: []` explicitly.
    std::fs::write(
        &path,
        r#"
socks5:
  listen: "127.0.0.1:1080"

uplink_group:
  - name: main

uplinks:
  - name: primary
    group: main
    tcp_ws_url: "wss://example.com/secret/tcp"
    method: chacha20-ietf-poly1305
    password: Secret0

route: []
"#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("empty") && msg.contains("route"),
        "got: {msg}"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_cli_override_with_uplink_group() {
    let path = std::env::temp_dir().join("outline-ws-rust-cli-override.toml");
    std::fs::write(
        &path,
        r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"

        [[uplinks]]
        name = "primary"
        group = "main"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"
        "#,
    )
    .unwrap();

    // CLI override conflicts with new-shape config.
    let args = super::Args::parse_from([
        "test",
        "--tcp-ws-url",
        "wss://override.example.com/cli/tcp",
    ]);
    let err = load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("CLI uplink overrides") && msg.contains("[[uplink_group]]"),
        "got: {msg}"
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_loads_multiple_route_files() {
    let dir = std::env::temp_dir().join("outline-ws-rust-route-files-ok");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let v4_path = dir.join("cn-v4.list");
    let v6_path = dir.join("cn-v6.list");
    std::fs::write(&v4_path, "1.0.0.0/8\n2.0.0.0/8\n").unwrap();
    std::fs::write(&v6_path, "2001:db8::/32\n").unwrap();
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"

        [[uplinks]]
        name = "primary"
        group = "main"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [[route]]
        default = true
        via = "main"

        [[route]]
        files = ["cn-v4.list", "cn-v6.list"]
        via = "main"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = load_config(&cfg_path, &args).await.unwrap();
    let routing = config.routing.expect("routing must be built");
    assert_eq!(routing.rules.len(), 1);
    let rule = &routing.rules[0];
    assert_eq!(rule.files.len(), 2);
    assert_eq!(rule.files[0], v4_path);
    assert_eq!(rule.files[1], v6_path);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn load_config_rejects_inverted_route_without_prefixes() {
    let path = std::env::temp_dir().join("outline-ws-rust-route-invert-empty.toml");
    std::fs::write(
        &path,
        r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[uplink_group]]
        name = "main"

        [[uplinks]]
        name = "primary"
        group = "main"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [[route]]
        default = true
        via = "main"

        [[route]]
        invert = true
        prefixes = []
        via = "main"
        "#,
    )
    .unwrap();

    // This is caught at load_routing_config validation (no prefixes/file) —
    // the inverted-empty-set safety net in RoutingTable::compile is a
    // defense-in-depth layer behind that. Either message is acceptable.
    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("prefixes") || msg.contains("invert"),
        "got: {msg}"
    );

    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "control")]
#[tokio::test]
async fn load_config_accepts_control_section_with_token() {
    let path = std::env::temp_dir().join("outline-ws-rust-control-ok.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"

        [control]
        listen = "127.0.0.1:9091"
        token = "topsecret"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = load_config(&path, &args).await.unwrap();
    let control = config.control.expect("control config present");
    assert_eq!(control.listen, "127.0.0.1:9091".parse::<SocketAddr>().unwrap());
    assert_eq!(control.token, "topsecret");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_control_listener_without_token() {
    let path = std::env::temp_dir().join("outline-ws-rust-control-no-token.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"

        [control]
        listen = "127.0.0.1:9091"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("token"), "got: {msg}");

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn load_config_rejects_control_token_without_listener() {
    let path = std::env::temp_dir().join("outline-ws-rust-control-no-listen.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"

        [control]
        token = "topsecret"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let err = load_config(&path, &args).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("listener"), "got: {msg}");

    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "control")]
#[tokio::test]
async fn load_config_reads_control_token_from_file() {
    let dir = std::env::temp_dir().join("outline-ws-rust-control-tokfile");
    std::fs::create_dir_all(&dir).unwrap();
    let token_path = dir.join("token");
    std::fs::write(&token_path, "  filetoken\n").unwrap();
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        r#"
        tcp_ws_url = "wss://example.com/secret/tcp"
        method = "chacha20-ietf-poly1305"
        password = "Secret0"

        [socks5]
        listen = "127.0.0.1:1080"

        [control]
        listen = "127.0.0.1:9091"
        token_file = "token"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = load_config(&path, &args).await.unwrap();
    assert_eq!(config.control.unwrap().token, "filetoken");

    let _ = std::fs::remove_dir_all(dir);
}
