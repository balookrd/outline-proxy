//! Sticky-route hot-path invariants.
//!
//! `preferred_sticky_index` runs on every dial. Re-stamping an unchanged entry
//! costs the group-wide sticky write lock for nothing, so the unchanged case
//! must stay on the read path — while a genuine change (different uplink, or a
//! TTL that has decayed past half) must still be persisted.

use std::time::Duration;

use socks5_proto::TargetAddr;
use tokio::time::{Instant, timeout};
use url::Url;

use crate::config::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TransportMode,
    UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::routing_key::RoutingKey;
use crate::types::{TransportKind, UplinkManager};

const STICKY_TTL: Duration = Duration::from_secs(300);

fn uplink(name: &str, host: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse(&format!("wss://{host}/tcp")).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(&format!("wss://{host}/udp")).unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
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
        padding: None,
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
        endpoint_check: false,
        endpoint_check_timeout: Duration::from_millis(2000),
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

fn lb() -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
        shared_resume: false,
        sticky_ttl: STICKY_TTL,
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
        tun_icmp_liveness_window: None,
        bypass_when_down: false,
    }
}

fn manager() -> UplinkManager {
    UplinkManager::new_for_test(
        "main",
        vec![uplink("up-a", "a.example.com"), uplink("up-b", "b.example.com")],
        probe_disabled(),
        lb(),
    )
    .unwrap()
}

fn target() -> TargetAddr {
    TargetAddr::Domain("example.com".to_string(), 443)
}

fn flow_key() -> RoutingKey {
    RoutingKey::Target {
        transport: TransportKind::Tcp,
        target: target(),
    }
}

async fn sticky_entry(manager: &UplinkManager, key: &RoutingKey) -> Option<(usize, Instant)> {
    manager
        .inner
        .sticky_routes
        .read()
        .await
        .get(key)
        .map(|route| (route.uplink_index, route.expires_at))
}

/// A repeat dial that re-confirms the same uplink must stay on the read path.
/// The write lock is group-wide, so re-stamping an identical entry on every
/// dial serialises the whole group's dispatch behind one lock for nothing.
///
/// Held read guard = a write attempt deadlocks: if the dial completes, no
/// write was taken.
#[tokio::test(start_paused = true)]
async fn repeat_dial_on_the_same_uplink_takes_no_sticky_write_lock() {
    let manager = manager();
    manager.test_set_tcp_health(0, true, 10).await;
    manager.test_set_tcp_health(1, true, 50).await;

    // First dial seeds the sticky entry (this one legitimately writes).
    let _ = manager.tcp_candidates(&target()).await;
    let (seeded_index, _) = sticky_entry(&manager, &flow_key())
        .await
        .expect("first dial must seed a sticky route");
    assert_eq!(seeded_index, 0, "the fastest healthy uplink must win the first dial");

    let guard = manager.inner.sticky_routes.read().await;
    let repeat = timeout(Duration::from_secs(5), manager.tcp_candidates(&target())).await;
    drop(guard);

    let candidates = repeat.expect("repeat dial must not take the sticky write lock");
    assert_eq!(
        candidates[0].index, 0,
        "the repeat dial must still be pinned to the same uplink"
    );
}

/// The read fast path must not let an entry rot: once the TTL has decayed past
/// half, the same-uplink decision is written back so the pin survives the
/// prune sweep.
#[tokio::test(start_paused = true)]
async fn sticky_route_is_refreshed_once_half_the_ttl_has_elapsed() {
    let manager = manager();
    manager.test_set_tcp_health(0, true, 10).await;
    manager.test_set_tcp_health(1, true, 50).await;

    let _ = manager.tcp_candidates(&target()).await;
    let (_, seeded_expiry) = sticky_entry(&manager, &flow_key())
        .await
        .expect("first dial must seed a sticky route");

    tokio::time::advance(STICKY_TTL / 2 + Duration::from_secs(1)).await;
    let _ = manager.tcp_candidates(&target()).await;

    let (index, refreshed_expiry) = sticky_entry(&manager, &flow_key())
        .await
        .expect("sticky route must survive the refresh");
    assert_eq!(index, 0, "the refresh must keep the same uplink");
    assert!(
        refreshed_expiry > seeded_expiry,
        "a dial past half the TTL must extend the entry ({refreshed_expiry:?} <= {seeded_expiry:?})",
    );
}

/// The fast path is keyed on the *decision*, not just on presence: when the
/// pinned uplink stops being healthy the entry must be rewritten to the
/// replacement rather than being skipped as "unchanged".
#[tokio::test(start_paused = true)]
async fn sticky_route_is_rewritten_when_the_pinned_uplink_goes_unhealthy() {
    let manager = manager();
    manager.test_set_tcp_health(0, true, 10).await;
    manager.test_set_tcp_health(1, true, 50).await;

    let _ = manager.tcp_candidates(&target()).await;
    assert_eq!(
        sticky_entry(&manager, &flow_key()).await.map(|(index, _)| index),
        Some(0),
        "first dial must pin the fastest healthy uplink",
    );

    manager.test_set_tcp_health(0, false, 0).await;
    let candidates = manager.tcp_candidates(&target()).await;

    assert_eq!(candidates[0].index, 1, "an unhealthy pin must fail over to the healthy uplink");
    assert_eq!(
        sticky_entry(&manager, &flow_key()).await.map(|(index, _)| index),
        Some(1),
        "the sticky entry must follow the failover, not stay on the dead uplink",
    );
}
