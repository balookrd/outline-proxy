use super::*;
use http::HeaderMap;
use outline_metrics::{StickyRouteSnapshot, UplinkManagerSnapshot, UplinkSnapshot};
use outline_uplink::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, ServerAddr,
    UplinkConfig, UplinkManager, UplinkRegistry, UplinkTransport, VlessUdpMuxLimits,
    WsProbeConfig, TransportMode,
};
use serde_json::Value;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use handlers::activate_from_json;
use server::{ControlState, handle_connection};
use topology::{
    ControlSummaryResponse, ControlTopologyResponse, build_instance_topology, build_summary,
};

/// Mirror of the predicate inside `is_authorized`. Kept in sync via the
/// shared `constant_time_eq` and the same parsing rule (`Bearer ` prefix,
/// then trim). Hyper's `Incoming` body type is opaque to test code, so we
/// exercise the header logic directly against a `HeaderMap`.
fn header_authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(header) = headers.get(AUTHORIZATION) else {
        return false;
    };
    let Ok(value) = header.to_str() else {
        return false;
    };
    let Some(presented) = value.strip_prefix("Bearer ").map(str::trim) else {
        return false;
    };
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

fn headers_with(authorization: Option<&str>) -> HeaderMap {
    let mut map = HeaderMap::new();
    if let Some(value) = authorization {
        map.insert(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
    }
    map
}

#[test]
fn constant_time_eq_matches_byte_for_byte() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
    assert!(!constant_time_eq(b"", b"x"));
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn rejects_missing_or_malformed_authorization() {
    assert!(!header_authorized(&headers_with(None), "secret"));
    assert!(!header_authorized(&headers_with(Some("Basic secret")), "secret"));
    assert!(!header_authorized(&headers_with(Some("bearer secret")), "secret"));
}

#[test]
fn accepts_matching_bearer_token() {
    assert!(header_authorized(&headers_with(Some("Bearer secret")), "secret"));
    assert!(header_authorized(&headers_with(Some("Bearer   secret  ")), "secret"));
}

#[test]
fn rejects_mismatched_bearer_token() {
    assert!(!header_authorized(&headers_with(Some("Bearer wrong")), "secret"));
    assert!(!header_authorized(&headers_with(Some("Bearer secre")), "secret"));
    assert!(!header_authorized(&headers_with(Some("Bearer secrett")), "secret"));
}

fn snapshot_fixture() -> Vec<UplinkManagerSnapshot> {
    vec![UplinkManagerSnapshot {
        group: "core".to_string(),
        generated_at_unix_ms: 42,
        load_balancing_mode: "active_passive".to_string(),
        routing_scope: "per_uplink".to_string(),
        auto_failback: false,
        global_active_uplink: Some("uplink-01".to_string()),
        global_active_reason: None,
        tcp_active_uplink: Some("uplink-02".to_string()),
        tcp_active_reason: None,
        udp_active_uplink: Some("uplink-01".to_string()),
        udp_active_reason: None,
        uplinks: vec![
            UplinkSnapshot {
                index: 0,
                name: "uplink-01".to_string(),
                group: "core".to_string(),
                transport: "ws".to_string(),
                tcp_mode: Some("ws_h2".to_string()),
                udp_mode: Some("ws_h3".to_string()),
                weight: 1.0,
                tcp_healthy: Some(true),
                udp_healthy: Some(false),
                tcp_latency_ms: None,
                udp_latency_ms: None,
                tcp_rtt_ewma_ms: None,
                udp_rtt_ewma_ms: None,
                tcp_penalty_ms: None,
                udp_penalty_ms: None,
                tcp_effective_latency_ms: None,
                udp_effective_latency_ms: None,
                tcp_score_ms: None,
                udp_score_ms: None,
                cooldown_tcp_ms: None,
                cooldown_udp_ms: None,
                last_checked_ago_ms: None,
                last_error: None,
                standby_tcp_ready: 0,
                standby_udp_ready: 0,
                tcp_consecutive_failures: 0,
                udp_consecutive_failures: 1,
                h3_tcp_downgrade_until_ms: None,
                h3_udp_downgrade_until_ms: None,
                tcp_mode_capped_to: None,
                udp_mode_capped_to: None,
                tcp_xhttp_submode: None,
                udp_xhttp_submode: None,
                tcp_xhttp_submode_block_remaining_ms: None,
                udp_xhttp_submode_block_remaining_ms: None,
                last_active_tcp_ago_ms: None,
                last_active_udp_ago_ms: None,
            },
            UplinkSnapshot {
                index: 1,
                name: "uplink-02".to_string(),
                group: "core".to_string(),
                transport: "vless".to_string(),
                tcp_mode: Some("quic".to_string()),
                udp_mode: Some("quic".to_string()),
                weight: 1.0,
                tcp_healthy: Some(false),
                udp_healthy: Some(true),
                tcp_latency_ms: None,
                udp_latency_ms: None,
                tcp_rtt_ewma_ms: None,
                udp_rtt_ewma_ms: None,
                tcp_penalty_ms: None,
                udp_penalty_ms: None,
                tcp_effective_latency_ms: None,
                udp_effective_latency_ms: None,
                tcp_score_ms: None,
                udp_score_ms: None,
                cooldown_tcp_ms: None,
                cooldown_udp_ms: None,
                last_checked_ago_ms: None,
                last_error: Some("tcp failed".to_string()),
                standby_tcp_ready: 0,
                standby_udp_ready: 0,
                tcp_consecutive_failures: 1,
                udp_consecutive_failures: 0,
                h3_tcp_downgrade_until_ms: None,
                h3_udp_downgrade_until_ms: None,
                tcp_mode_capped_to: None,
                udp_mode_capped_to: None,
                tcp_xhttp_submode: None,
                udp_xhttp_submode: None,
                tcp_xhttp_submode_block_remaining_ms: None,
                udp_xhttp_submode_block_remaining_ms: None,
                last_active_tcp_ago_ms: None,
                last_active_udp_ago_ms: None,
            },
        ],
        sticky_routes: vec![StickyRouteSnapshot {
            key: "example".to_string(),
            uplink_index: 0,
            uplink_name: "uplink-01".to_string(),
            expires_in_ms: 500,
        }],
    }]
}

fn test_uplink(name: &str, addr: SocketAddr) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Shadowsocks,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: Some(addr.to_string().parse::<ServerAddr>().unwrap()),
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        }
}

fn lb() -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActivePassive,
        routing_scope: RoutingScope::Global,
        sticky_ttl: Duration::from_secs(0),
        hysteresis: Duration::from_millis(0),
        failure_cooldown: Duration::from_secs(5),
        tcp_chunk0_failover_timeout: Duration::from_secs(10),
        auto_failback: false,
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.3,
        failure_penalty: Duration::from_millis(500),
        failure_penalty_max: Duration::from_secs(30),
        failure_penalty_halflife: Duration::from_secs(60),
        mode_downgrade_duration: Duration::from_secs(60),
        runtime_failure_window: Duration::from_secs(60),
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
    }
}

fn probe_disabled() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(10),
        timeout: Duration::from_millis(200),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 1,
        attempts: 1,
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
    }
}

#[test]
fn topology_serialization_shape_has_active_flags() {
    let topology = ControlTopologyResponse {
        instance: build_instance_topology(&snapshot_fixture()),
    };
    let json: Value = serde_json::to_value(topology).unwrap();
    assert_eq!(json["instance"]["groups"][0]["name"], "core");
    assert_eq!(json["instance"]["groups"][0]["uplinks"][0]["active_global"], true);
    assert_eq!(json["instance"]["groups"][0]["uplinks"][0]["active_tcp"], false);
    assert_eq!(json["instance"]["groups"][0]["uplinks"][1]["active_tcp"], true);
    assert_eq!(json["instance"]["groups"][0]["uplinks"][1]["last_error"], "tcp failed");
}

#[test]
fn summary_counts_match_fixture() {
    let summary = build_summary(&snapshot_fixture());
    assert_eq!(
        summary,
        ControlSummaryResponse {
            groups_total: 1,
            uplinks_total: 2,
            tcp_healthy: 1,
            tcp_unhealthy: 1,
            udp_healthy: 1,
            udp_unhealthy: 1,
            active_global: 1,
            active_tcp: 1,
            active_udp: 1,
        }
    );
}

#[test]
fn rejects_bad_method_for_activate() {
    let response = require_method(&Method::GET, Method::POST, "POST").unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn activate_rejects_bad_input() {
    let response = activate_from_json(br#"{"group":"core"}"#, test_registry()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn activate_succeeds_for_existing_uplink() {
    let response = activate_from_json(
        br#"{"group":"core","uplink":"uplink-02","transport":"tcp"}"#,
        test_registry(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn endpoint_requires_auth() {
    let (status, _body) = send_raw_http(
        "GET /control/topology HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        test_registry(),
        "token",
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn endpoint_rejects_bad_method() {
    let (status, body) = send_raw_http(
        "PUT /control/summary HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer token\r\nConnection: close\r\n\r\n",
        test_registry(),
        "token",
    )
    .await;
    assert_eq!(status, 405);
    assert!(body.contains("use GET"));
}

#[tokio::test]
async fn endpoint_serializes_topology() {
    let (status, body) = send_raw_http(
        "GET /control/topology HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer token\r\nConnection: close\r\n\r\n",
        test_registry(),
        "token",
    )
    .await;
    assert_eq!(status, 200);
    let json: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["instance"]["groups"][0]["name"], "core");
    assert!(json["instance"]["groups"][0]["uplinks"][0]
        .get("active_global")
        .is_some());
}

fn test_registry() -> UplinkRegistry {
    let addr: SocketAddr = (Ipv4Addr::LOCALHOST, 8388).into();
    let manager = UplinkManager::new_for_test(
        "core",
        vec![test_uplink("uplink-01", addr), test_uplink("uplink-02", addr)],
        probe_disabled(),
        lb(),
    )
    .unwrap();
    UplinkRegistry::from_single_manager(manager)
}

async fn send_raw_http(
    raw_request: &str,
    uplinks: UplinkRegistry,
    token: &str,
) -> (u16, String) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(ControlState {
        token: token.to_string(),
        uplinks,
        config_path: None,
        config_write_lock: tokio::sync::Mutex::new(()),
        apply: None,
    });
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handle_connection(stream, state).await.unwrap();
    });

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client.write_all(raw_request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    server_task.await.unwrap();

    let response = String::from_utf8(response).unwrap();
    let mut parts = response.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default().to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, body)
}
