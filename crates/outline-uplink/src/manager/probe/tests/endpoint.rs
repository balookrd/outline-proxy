//! Unit tests for the endpoint-reachability verdict.
//!
//! The check itself needs sockets (covered in `probe/tests/endpoint.rs`);
//! what matters here is what the manager does with its answer — the streak
//! gate, the condemnation it triggers, and the two things it must leave
//! alone: the carrier-descent stack and a plane no wire can carry.

use std::time::Duration;

use crate::config::{
    CipherKind, FallbackTransport, LoadBalancingConfig, LoadBalancingMode, ProbeConfig,
    RoutingScope, TransportMode, UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::types::{TransportKind, UplinkManager};

fn probe_cfg(min_failures: usize) -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(10),
        timeout: Duration::from_secs(10),
        max_concurrent: 1,
        max_dials: 1,
        min_failures,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
        endpoint_check: true,
        endpoint_check_timeout: Duration::from_millis(500),
        ws: WsProbeConfig { enabled: true },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

fn lb_cfg() -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActivePassive,
        routing_scope: RoutingScope::Global,
        shared_resume: false,
        sticky_ttl: Duration::from_secs(300),
        hysteresis: Duration::from_millis(50),
        failure_cooldown: Duration::from_secs(10),
        tcp_chunk0_failover_timeout: Duration::from_secs(10),
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.3,
        failure_penalty: Duration::from_millis(500),
        failure_penalty_max: Duration::from_secs(30),
        failure_penalty_halflife: Duration::from_secs(60),
        mode_downgrade_duration: Duration::from_secs(60),
        runtime_failure_window: Duration::from_secs(60),
        chunk0_failure_window: Duration::from_secs(300),
        global_udp_strict_health: false,
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        warm_probe_keepalive_interval: None,
        auto_failback: false,
        health_weighted_selection: false,
        health_weight_floor: 0.05,
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
        tcp_mid_session_retry_buffer_bytes: 256 * 1024,
        tcp_mid_session_retry_budget: 1,
        tcp_mid_session_retry_overflow_policy: crate::OverflowPolicy::Soft,
        tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        bypass_when_down: false,
    }
}

/// VLESS-over-XHTTP primary with one WS fallback on the same host — the
/// shape the check is built for (every wire behind one endpoint).
fn uplink_with_fallback(udp_capable: bool) -> UplinkConfig {
    UplinkConfig {
        name: "edge".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: None,
        tcp_xhttp_url: Some(url::Url::parse("https://edge.example.com:6443/x").unwrap()),
        tcp_mode: TransportMode::XhttpH3,
        udp_ws_url: None,
        udp_xhttp_url: udp_capable
            .then(|| url::Url::parse("https://edge.example.com:6443/xu").unwrap()),
        udp_mode: TransportMode::XhttpH3,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: vec![FallbackTransport {
            transport: UplinkTransport::Ss,
            tcp_ws_url: Some(url::Url::parse("wss://edge.example.com:6443/ws").unwrap()),
            tcp_xhttp_url: None,
            tcp_mode: TransportMode::WsH3,
            udp_ws_url: udp_capable
                .then(|| url::Url::parse("wss://edge.example.com:6443/wsu").unwrap()),
            udp_xhttp_url: None,
            udp_mode: TransportMode::WsH3,
            vless_ws_url: None,
            vless_xhttp_url: None,
            vless_mode: TransportMode::WsH1,
            ss_ws_url: None,
            ss_xhttp_url: None,
            ss_mode: None,
            vless_id: None,
            cipher: CipherKind::Chacha20IetfPoly1305,
            password: "secret".to_string(),
            fwmark: None,
            ipv6_first: false,
            fingerprint_profile: None,
        }],
        shuffle_wires: true,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

fn manager(min_failures: usize, udp_capable: bool) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![uplink_with_fallback(udp_capable)],
        probe_cfg(min_failures),
        lb_cfg(),
    )
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn single_unreachable_cycle_does_not_condemn_below_min_failures() {
    let manager = manager(2, true);
    let uplink = manager.inner.uplinks[0].clone();

    let condemned = manager.note_endpoint_unreachable(0, &uplink, "edge.example.com:6443");

    assert!(!condemned, "one failed cycle must not be enough with min_failures = 2");
    let status = manager.inner.read_status(0);
    assert_eq!(status.endpoint_unreachable_streak, 1);
    assert_eq!(status.tcp.healthy, None, "health verdict stays with the regular probe");
    assert!(status.tcp.cooldown_until.is_none());
}

#[tokio::test(start_paused = true)]
async fn streak_at_min_failures_condemns_both_planes() {
    let manager = manager(2, true);
    let uplink = manager.inner.uplinks[0].clone();

    assert!(!manager.note_endpoint_unreachable(0, &uplink, "edge.example.com:6443"));
    let condemned = manager.note_endpoint_unreachable(0, &uplink, "edge.example.com:6443");

    assert!(condemned);
    let status = manager.inner.read_status(0);
    assert_eq!(status.tcp.healthy, Some(false));
    assert_eq!(status.udp.healthy, Some(false));
    assert!(status.tcp.cooldown_until.is_some(), "candidate filter must drop the uplink");
    assert!(status.udp.cooldown_until.is_some());
    assert_eq!(
        status.tcp.wires_failed_in_round, 0,
        "a dead host is not a wire-rotation problem",
    );
    assert!(
        status
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("edge.example.com:6443"),
        "the dashboard chip must name the endpoint that refused",
    );
}

#[tokio::test(start_paused = true)]
async fn condemnation_leaves_the_carrier_stack_alone() {
    // Dropping h3 → h2 cannot help when nothing is listening, and a cap
    // installed here would outlive the outage.
    let manager = manager(1, true);
    let uplink = manager.inner.uplinks[0].clone();

    assert!(manager.note_endpoint_unreachable(0, &uplink, "edge.example.com:6443"));

    assert_eq!(
        manager.effective_tcp_mode(0).await,
        TransportMode::XhttpH3,
        "the configured carrier must survive a host-level outage",
    );
    assert_eq!(manager.effective_tcp_mode_for_wire(0, 1).await, TransportMode::WsH3);
}

#[tokio::test(start_paused = true)]
async fn condemnation_ages_out_the_any_wire_liveness_stamp() {
    // `health_effective` treats a recent any-wire success as liveness, so a
    // condemned uplink that kept a fresh stamp would keep rendering "Ready".
    let manager = manager(1, true);
    let uplink = manager.inner.uplinks[0].clone();
    manager.mark_wire_data_proven(0, TransportKind::Tcp);
    assert!(manager.inner.read_status(0).tcp.last_any_wire_success.is_some());

    assert!(manager.note_endpoint_unreachable(0, &uplink, "edge.example.com:6443"));

    let status = manager.inner.read_status(0);
    let last = status
        .tcp
        .last_any_wire_success
        .expect("stamp stays present, just stale");
    assert!(
        tokio::time::Instant::now().saturating_duration_since(last)
            >= lb_cfg().runtime_failure_window,
        "the stamp must fall outside the runtime-failure window",
    );
}

#[tokio::test(start_paused = true)]
async fn udp_plane_is_untouched_when_no_wire_can_carry_udp() {
    let manager = manager(1, false);
    let uplink = manager.inner.uplinks[0].clone();

    assert!(manager.note_endpoint_unreachable(0, &uplink, "edge.example.com:6443"));

    let status = manager.inner.read_status(0);
    assert_eq!(status.tcp.healthy, Some(false));
    assert_eq!(
        status.udp.healthy, None,
        "a TCP-only uplink must not acquire a UDP health verdict",
    );
}

#[tokio::test(start_paused = true)]
async fn a_reachable_endpoint_resets_the_streak() {
    let manager = manager(3, true);
    let uplink = manager.inner.uplinks[0].clone();

    assert!(!manager.note_endpoint_unreachable(0, &uplink, "edge.example.com:6443"));
    manager.note_endpoint_reachable(0);

    assert_eq!(manager.inner.read_status(0).endpoint_unreachable_streak, 0);
    assert_eq!(
        manager.inner.read_status(0).tcp.healthy,
        None,
        "reachability alone never asserts health",
    );
}
