//! Weighted, liveness-aware wire (sub-uplink) selection.
//!
//! These tests cover the `health_weighted_selection` behaviour layered on top
//! of the sticky active-wire state machine: a wire that disconnects often
//! accrues a decaying penalty, is dialed less frequently, but is never dropped
//! from the cascade and recovers as the penalty decays. With the feature off,
//! the legacy cyclic dial order is preserved byte-for-byte.

use std::time::Duration;

use url::Url;

use crate::config::{
    CipherKind, FallbackTransport, LoadBalancingConfig, LoadBalancingMode, ProbeConfig,
    RoutingScope, TransportMode, UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::types::{TransportKind, UplinkManager};

fn ss_fallback(tag: &str) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse(&format!("wss://host.example.com/{tag}/tcp")).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(&format!("wss://host.example.com/{tag}/udp")).unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "Secret0".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

/// Primary + two fallbacks = three wires.
fn three_wire_uplink() -> UplinkConfig {
    UplinkConfig {
        name: "up".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://host.example.com/primary/tcp").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse("wss://host.example.com/primary/udp").unwrap()),
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
        fallbacks: vec![ss_fallback("fb1"), ss_fallback("fb2")],
        shuffle_wires: false,
        carrier_downgrade: false,
        padding: None,
        shuffle_timer: None,
    }
}

fn probe() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(10),
        timeout: Duration::from_secs(10),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 2,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
        endpoint_check: false,
        endpoint_check_timeout: Duration::from_millis(2000),
        ws: WsProbeConfig { enabled: true },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

fn lb(weighted: bool) -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
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
        health_weighted_selection: weighted,
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

fn manager(weighted: bool) -> UplinkManager {
    UplinkManager::new_for_test("main", vec![three_wire_uplink()], probe(), lb(weighted)).unwrap()
}

#[tokio::test]
async fn failure_penalises_only_the_attempted_wire() {
    let mgr = manager(true);
    // A failed dial on wire 2 (a non-active wire) still records its penalty, so
    // the weighted order learns about every wire's health, not just the active.
    mgr.record_wire_outcome(0, TransportKind::Tcp, 2, false, 3);
    let st = mgr.read_status_for_test(0);
    let penalty = |w: usize| st.tcp.wire_penalty.get(w).map_or(0.0, |s| s.value_secs);
    assert!(penalty(2) > 0.0, "the attempted wire accrues penalty: {}", penalty(2));
    assert_eq!(penalty(0), 0.0, "the untried primary stays unpenalised");
    assert_eq!(penalty(1), 0.0, "the untried fallback stays unpenalised");
}

#[tokio::test]
async fn proven_delivery_clears_active_wire_penalty() {
    let mgr = manager(true);
    mgr.test_set_active_wire(0, TransportKind::Tcp, 1);
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 1, 5);
    assert!(
        mgr.read_status_for_test(0).tcp.wire_penalty[1].value_secs > 0.0,
        "precondition: wire 1 is penalised",
    );
    mgr.mark_wire_data_proven(0, TransportKind::Tcp);
    assert_eq!(
        mgr.read_status_for_test(0).tcp.wire_penalty[1].value_secs,
        0.0,
        "proven end-to-end delivery resets the active wire's penalty",
    );
}

#[tokio::test]
async fn disabled_keeps_cyclic_dial_order() {
    let mgr = manager(false);
    // Legacy behaviour: cyclic order starting at the active wire, penalties
    // ignored entirely.
    assert_eq!(mgr.wire_dial_order(0, TransportKind::Tcp, 3), vec![0, 1, 2]);
    mgr.test_set_active_wire(0, TransportKind::Tcp, 1);
    assert_eq!(mgr.wire_dial_order(0, TransportKind::Tcp, 3), vec![1, 2, 0]);
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 1, 50);
    assert_eq!(
        mgr.wire_dial_order(0, TransportKind::Tcp, 3),
        vec![1, 2, 0],
        "with the feature off, a heavy penalty does not reorder the chain",
    );
}

#[tokio::test]
async fn weighted_order_demotes_flaky_wire_but_keeps_it_reachable() {
    let mgr = manager(true);
    // Wire 0 disconnects constantly; wires 1 and 2 stay healthy.
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 0, 60);
    let trials = 5_000;
    let mut first_is_flaky = 0u32;
    let mut flaky_present = 0u32;
    for _ in 0..trials {
        let order = mgr.wire_dial_order(0, TransportKind::Tcp, 3);
        assert_eq!(order.len(), 3);
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2], "the cascade still contains every wire");
        if order[0] == 0 {
            first_is_flaky += 1;
        }
        if order.contains(&0) {
            flaky_present += 1;
        }
    }
    assert_eq!(flaky_present, trials, "the flaky wire is never dropped from the order");
    // Expected ~floor/(floor+1+1) ≈ 2.4%; assert well under a third yet non-zero.
    assert!(
        first_is_flaky < trials / 6,
        "the flaky wire is rarely dialed first: {first_is_flaky}/{trials}"
    );
    assert!(
        first_is_flaky > 0,
        "but the floor still lets it lead occasionally: {first_is_flaky}/{trials}"
    );
}

#[tokio::test]
async fn weighted_rotate_avoids_flaky_wire_but_not_entirely() {
    let mgr = manager(true);
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 0, 60);
    mgr.test_add_wire_penalty(0, TransportKind::Udp, 0, 60);
    let trials = 3_000;
    let mut tcp_hits = [0u32; 3];
    for _ in 0..trials {
        let (tcp_wire, _udp_wire) = mgr.rotate_active_wire(0).expect("multi-wire uplink rerolls");
        tcp_hits[tcp_wire as usize] += 1;
    }
    assert!(
        tcp_hits[0] < tcp_hits[1] && tcp_hits[0] < tcp_hits[2],
        "the anti-DPI reroll lands on the flaky wire least often: {tcp_hits:?}"
    );
    assert!(tcp_hits[0] > 0, "but the floor keeps the flaky wire reachable: {tcp_hits:?}");
}

#[tokio::test]
async fn reroll_clears_the_per_wire_carrier_caps_of_a_proven_uplink() {
    // The shuffle_timer reroll wipes primary's descent when the uplink is
    // still proving delivery — the new wire's carrier stack starts fresh at
    // the configured rank. The per-wire slots must go with it: a cap earned
    // by the wire we are rotating away from must not decide the dial mode of
    // whichever wire the next reroll lands on, and (unlike primary) nothing
    // but the TTL would otherwise clear it.
    let mut cfg = three_wire_uplink();
    cfg.fallbacks[0].tcp_mode = TransportMode::WsH3;
    cfg.carrier_downgrade = true; // this fixture opts out by default
    let mgr = UplinkManager::new_for_test("g", vec![cfg], probe(), lb(false)).unwrap();

    mgr.note_silent_transport_fallback_for_wire(0, TransportKind::Tcp, 1, TransportMode::WsH3);
    assert_eq!(mgr.effective_tcp_mode_for_wire(0, 1).await, TransportMode::WsH2);

    // Stamp proven delivery so the reroll takes its "healthy uplink" arm.
    mgr.mark_wire_data_proven(0, TransportKind::Tcp);
    mgr.rotate_active_wire(0).expect("multi-wire uplink rerolls");

    assert_eq!(
        mgr.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH3,
        "the reroll must clear the fallback wire's cap along with primary's",
    );
}

/// `shared_resume` scopes the resume-cache key to the group name for **both**
/// transports, so every uplink in a mesh-cluster group presents one
/// `X-Outline-Resume` id and a session survives an edge switch. Off (the default)
/// keeps the per-uplink scope so independent servers never cross-resume. UDP
/// shares the scope just like TCP: a group-shared UDP id carries a fixed home
/// shard, so when the rotating UDP wire lands on a non-home edge the server
/// relays the datagram carrier to the home over the mesh — the intended
/// cross-node path (the home's per-session NAT scope keeps concurrent carriers
/// from colliding). The `#tcp` / `#udp` suffix still separates the two
/// transports' Session IDs within one scope.
#[test]
fn shared_resume_scopes_the_resume_key_to_the_group_for_both_transports() {
    let uplink = three_wire_uplink(); // name = "up"

    let per_uplink =
        UplinkManager::new_for_test("cluster-a", vec![uplink.clone()], probe(), lb(false)).unwrap();
    assert_eq!(per_uplink.resume_cache_key_for("up", "tcp"), "up#tcp");
    assert_eq!(per_uplink.resume_cache_key_for("edge-b", "udp"), "edge-b#udp");

    let shared = UplinkManager::new_for_test(
        "cluster-a",
        vec![uplink],
        probe(),
        LoadBalancingConfig { shared_resume: true, ..lb(false) },
    )
    .unwrap();
    // Both transports share the group scope; the transport suffix keeps their
    // Session IDs in distinct cache slots.
    assert_eq!(shared.resume_cache_key_for("up", "tcp"), "cluster-a#tcp");
    assert_eq!(shared.resume_cache_key_for("edge-b", "udp"), "cluster-a#udp");
}
