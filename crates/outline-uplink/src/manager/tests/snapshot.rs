use std::time::Duration;

use url::Url;

use crate::config::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TransportMode,
    UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::types::UplinkManager;

fn uplink() -> UplinkConfig {
    UplinkConfig {
        name: "primary".to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://main.example.com/tcp").unwrap()),
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse("wss://main.example.com/udp").unwrap()),
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
        shuffle_timer: None,
    }
}

fn probe_disabled() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(5),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 1,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

fn lb(bypass_when_down: bool) -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
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
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
        tcp_mid_session_retry_buffer_bytes: 256 * 1024,
        tcp_mid_session_retry_budget: 1,
        tcp_mid_session_retry_overflow_policy: crate::OverflowPolicy::Soft,
        tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        bypass_when_down,
    }
}

fn manager(bypass_when_down: bool) -> UplinkManager {
    UplinkManager::new_for_test("main", vec![uplink()], probe_disabled(), lb(bypass_when_down))
        .unwrap()
}

/// The snapshot's `bypass_active_*` bits must track the same per-transport
/// `has_any_healthy` signal the dispatch layer uses: a fresh manager has no
/// probe verdict (counts as down), and each transport clears its bit
/// independently as soon as one uplink of that transport recovers.
#[tokio::test]
async fn snapshot_reports_live_bypass_state() {
    let manager = manager(true);

    let snap = manager.snapshot().await;
    assert!(snap.bypass_when_down);
    assert!(snap.bypass_active_tcp);
    assert!(snap.bypass_active_udp);

    manager.test_set_tcp_health(0, true, 50).await;
    let snap = manager.snapshot().await;
    assert!(!snap.bypass_active_tcp);
    assert!(snap.bypass_active_udp);

    manager.test_set_udp_health(0, true, 50).await;
    let snap = manager.snapshot().await;
    assert!(!snap.bypass_active_tcp);
    assert!(!snap.bypass_active_udp);
}

#[tokio::test]
async fn snapshot_keeps_bypass_inactive_when_opted_out() {
    // Down group without the flag: the config bit and both active bits
    // stay false, so metrics / topology / dashboard render nothing.
    let manager = manager(false);
    let snap = manager.snapshot().await;
    assert!(!snap.bypass_when_down);
    assert!(!snap.bypass_active_tcp);
    assert!(!snap.bypass_active_udp);
}
