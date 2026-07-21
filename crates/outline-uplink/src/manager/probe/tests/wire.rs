//! Unit tests for the per-wire probe helpers.
//!
//! The end-to-end fallback-wire probe loop talks to a real network, so the
//! tests here cover the pure pieces: wire-view materialisation, the
//! "which wire is the probe target" decision, and the carrier-outcome seam
//! (`note_fallback_wire_carrier_outcome`) — which is where the probe's
//! result is turned into descent / recovery on that wire's own slot, and is
//! callable with no sockets at all. Integration with the probe machinery is
//! exercised by the existing snapshot tests in `tests/fallback.rs` plus
//! manual verification.

use std::time::Duration;

use super::{WireProbePlane, target_wire_for_fallback_probe};

use crate::config::{
    CipherKind, FallbackTransport, LoadBalancingConfig, LoadBalancingMode, ProbeConfig,
    RoutingScope, TransportMode, UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::types::{TransportKind, UplinkManager};

fn vless_xhttp_primary() -> UplinkConfig {
    UplinkConfig {
        name: "edge".to_string(),
        transport: UplinkTransport::Vless,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: Some(url::Url::parse("https://cdn.example.com/SECRET/xhttp").unwrap()),
        vless_mode: TransportMode::XhttpH3,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: Some([0u8; 16]),
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

fn ws_fallback() -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(url::Url::parse("wss://ws.example.com/tcp").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH2,
        udp_ws_url: Some(url::Url::parse("wss://ws.example.com/udp").unwrap()),
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
        password: "shared".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

fn vless_fallback() -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Vless,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: Some(url::Url::parse("wss://vless.example.com/ws").unwrap()),
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH2,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: Some([1u8; 16]),
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "shared".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

#[test]
fn wire_view_index_zero_returns_primary_with_empty_fallbacks() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(), vless_fallback()];

    let view = cfg.wire_view(0).expect("primary view exists");
    assert_eq!(view.transport, UplinkTransport::Vless);
    assert_eq!(view.vless_mode, TransportMode::XhttpH3);
    assert!(
        view.fallbacks.is_empty(),
        "wire view must not carry the parent's fallbacks (probe code path treats it as a single wire)",
    );
    assert_eq!(view.name, "edge");
}

#[test]
fn wire_view_first_fallback_is_synthetic_uplink_with_fallback_fields() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(), vless_fallback()];

    let view = cfg.wire_view(1).expect("first fallback view exists");
    assert_eq!(view.transport, UplinkTransport::Ss);
    assert_eq!(view.tcp_mode, TransportMode::WsH2);
    assert_eq!(view.tcp_ws_url.as_ref().unwrap().as_str(), "wss://ws.example.com/tcp",);
    assert!(view.fallbacks.is_empty());
    // Identity fields inherited from parent for log/metric attribution.
    assert_eq!(view.name, "edge");
    assert_eq!(view.weight, 1.0);
}

#[test]
fn wire_view_second_fallback_walks_chain() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(), vless_fallback()];

    let view = cfg.wire_view(2).expect("second fallback view exists");
    assert_eq!(view.transport, UplinkTransport::Vless);
    assert_eq!(view.vless_ws_url.as_ref().unwrap().as_str(), "wss://vless.example.com/ws");
}

#[test]
fn wire_view_out_of_range_is_none() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback()];
    assert!(cfg.wire_view(2).is_none());
}

#[test]
fn target_wire_picks_first_fallback_when_active_still_on_primary() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback()];
    // Both transports report active_wire = 0 (failure streak hasn't crossed
    // min_failures yet) — bootstrap path: still probe wire 1 so the failing
    // primary's first cycle gets its fallback validated immediately.
    assert_eq!(target_wire_for_fallback_probe(&cfg, 0, 0), Some(1));
}

#[test]
fn target_wire_follows_active_wire_when_advanced() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(), vless_fallback()];
    // TCP has flipped to wire 2, UDP still on wire 1 — probe whichever is
    // furthest along, so we validate the wire that any new TCP session
    // would actually land on.
    assert_eq!(target_wire_for_fallback_probe(&cfg, 2, 1), Some(2));
}

#[test]
fn target_wire_none_when_no_fallbacks() {
    let cfg = vless_xhttp_primary();
    assert!(target_wire_for_fallback_probe(&cfg, 0, 0).is_none());
}

#[test]
fn target_wire_none_when_active_index_overflows_chain() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback()];
    // Defensive: a stale active_wire value past the configured chain
    // length must not cause a panic from `wire_view`. Returns None so the
    // caller silently skips this cycle and lets the next reload settle.
    assert!(target_wire_for_fallback_probe(&cfg, 5, 0).is_none());
}

// ── Fallback-wire probe → that wire's carrier-descent slot ──────────────────
//
// `note_fallback_wire_carrier_outcome` is the seam where a fallback-wire
// probe result becomes descent or recovery on the wire's own slot. The probe
// itself needs a network; this seam does not, so the rules are pinned here:
// only the carrier signal may drive the cascade, a live carrier with a dead
// exit leg is inert, and recovery needs a streak.

fn lb_for_wire_probe() -> LoadBalancingConfig {
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

fn probe_cfg_for_wire_probe() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(10),
        timeout: Duration::from_secs(10),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 1,
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

/// Uplink whose wire 1 is a WS fallback dialing `ws_h3`, so its descent
/// stack has two ranks left (`ws_h2`, `ws_h1`) and cap moves are visible.
fn manager_with_h3_fallback(shuffle_wires: bool) -> UplinkManager {
    let mut cfg = vless_xhttp_primary();
    let mut fb = ws_fallback();
    fb.tcp_mode = TransportMode::WsH3;
    cfg.fallbacks = vec![fb];
    cfg.shuffle_wires = shuffle_wires;
    UplinkManager::new_for_test("test", vec![cfg], probe_cfg_for_wire_probe(), lb_for_wire_probe())
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn fallback_wire_carrier_failure_caps_that_wire() {
    let manager = manager_with_h3_fallback(false);
    manager.note_fallback_wire_carrier_outcome(
        0,
        TransportKind::Tcp,
        1,
        WireProbePlane {
            dialed_mode: TransportMode::WsH3,
            carrier_ok: false,
            site_ok: false,
            downgraded_from: None,
        },
    );
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH2,
        "a fallback-wire carrier failure must walk that wire's carrier down",
    );
    assert_eq!(
        manager.effective_tcp_mode(0).await,
        TransportMode::XhttpH3,
        "and must not touch the primary's carrier",
    );
}

#[tokio::test(start_paused = true)]
async fn fallback_wire_dead_exit_leg_leaves_the_carrier_alone() {
    // The regression 7196a62d fixed, in per-wire form: the carrier handshake
    // to our uplink server is up, only the far exit leg is unreachable.
    // Capping here would strand the wire on a slower carrier without touching
    // the actual problem, which lives past the uplink server.
    let manager = manager_with_h3_fallback(false);
    manager.note_fallback_wire_carrier_outcome(
        0,
        TransportKind::Tcp,
        1,
        WireProbePlane {
            dialed_mode: TransportMode::WsH3,
            carrier_ok: true,
            site_ok: false,
            downgraded_from: None,
        },
    );
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH3,
        "site-reachability failure must never drive the carrier cascade",
    );
}

#[tokio::test(start_paused = true)]
async fn fallback_wire_silent_downgrade_caps_the_requested_rank() {
    let manager = manager_with_h3_fallback(false);
    manager.note_fallback_wire_carrier_outcome(
        0,
        TransportKind::Tcp,
        1,
        WireProbePlane {
            dialed_mode: TransportMode::WsH3,
            carrier_ok: true,
            site_ok: true,
            downgraded_from: Some(TransportMode::WsH3),
        },
    );
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH2,
        "a silent fallback observed by the probe must cap the wire it happened on",
    );
}

/// Replays what `run_fallback_wire_probe` does for one TCP cycle: dial the
/// wire's *effective* carrier, then feed the outcome to the descent slot.
async fn probe_cycle(manager: &UplinkManager, carrier_ok: bool, site_ok: bool) {
    let dialed = manager.effective_tcp_mode_for_wire(0, 1).await;
    manager.note_fallback_wire_carrier_outcome(
        0,
        TransportKind::Tcp,
        1,
        WireProbePlane {
            dialed_mode: dialed,
            carrier_ok,
            site_ok,
            downgraded_from: None,
        },
    );
}

#[tokio::test(start_paused = true)]
async fn fallback_wire_walk_up_needs_a_streak_then_reclaims_a_rank() {
    // min_failures = 2 so the streaks are observable rather than instant.
    let mut cfg = vless_xhttp_primary();
    let mut fb = ws_fallback();
    fb.tcp_mode = TransportMode::WsH3;
    cfg.fallbacks = vec![fb];
    let mut probe = probe_cfg_for_wire_probe();
    probe.min_failures = 2;
    let manager =
        UplinkManager::new_for_test("test", vec![cfg], probe, lb_for_wire_probe()).unwrap();

    // Walk the wire down to its ws_h1 floor: the first failure installs
    // ws_h2, the second — now dialing ws_h2 — steps to ws_h1 once this
    // wire's own probe-failure streak reaches min_failures.
    probe_cycle(&manager, false, false).await;
    assert_eq!(manager.effective_tcp_mode_for_wire(0, 1).await, TransportMode::WsH2);
    probe_cycle(&manager, false, false).await;
    assert_eq!(manager.effective_tcp_mode_for_wire(0, 1).await, TransportMode::WsH1);

    // One success on the capped carrier is not enough to claw a rank back.
    probe_cycle(&manager, true, true).await;
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH1,
        "a single success must not walk the cap up",
    );

    // The second consecutive success meets the threshold.
    probe_cycle(&manager, true, true).await;
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH2,
        "two consecutive successes on the capped carrier walk it up one rank",
    );

    // The last hop back onto configured is the TTL's alone — same rule as
    // primary, where it belongs to the recovery probe a fallback wire lacks.
    for _ in 0..4 {
        probe_cycle(&manager, true, true).await;
    }
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH2,
        "walk-up must not promote onto the configured rank; the window's TTL does that",
    );
}

#[tokio::test(start_paused = true)]
async fn fallback_wire_dead_exit_leg_neither_descends_nor_walks_up() {
    // A live carrier with an unreachable target must be inert for the
    // cascade in both directions: it is not evidence about the carrier.
    let manager = manager_with_h3_fallback(false);
    probe_cycle(&manager, false, false).await;
    assert_eq!(manager.effective_tcp_mode_for_wire(0, 1).await, TransportMode::WsH2);

    for _ in 0..4 {
        probe_cycle(&manager, true, false).await;
    }
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH2,
        "exit-leg failures must neither deepen the cap nor lift it",
    );
}

#[tokio::test(start_paused = true)]
async fn fallback_wire_probe_failures_rotate_off_the_wire_once_it_hits_its_floor() {
    // The passive-uplink case this whole path exists for, end to end: no
    // client traffic, so only the fallback-wire probe can move things. It
    // replays what `run_fallback_wire_probe` does on a carrier failure —
    // feed the carrier outcome, then the wire outcome — and the wire must
    // walk `ws_h3 → ws_h2 → ws_h1` and only then rotate. Before the carrier
    // outcome was wired in, the slot stayed empty, the floor gate never
    // released, and active_wire sat on the broken wire forever.
    let manager = manager_with_h3_fallback(true);
    let total_wires = 2;

    manager.test_set_active_wire(0, TransportKind::Tcp, 1);

    probe_cycle(&manager, false, false).await;
    manager.record_wire_outcome(0, TransportKind::Tcp, 1, false, total_wires);
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        1,
        "rotation must wait while wire 1 still has carrier ranks left",
    );
    assert_eq!(manager.effective_tcp_mode_for_wire(0, 1).await, TransportMode::WsH2);

    probe_cycle(&manager, false, false).await;
    manager.record_wire_outcome(0, TransportKind::Tcp, 1, false, total_wires);
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH1,
        "the second failure — now dialing ws_h2 — reaches the wire's floor",
    );
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        0,
        "at the ws_h1 floor the gate releases and the probe rotates off the wire",
    );
}

#[tokio::test(start_paused = true)]
async fn fallback_wire_success_streak_resets_on_a_fresh_descent() {
    // min_failures = 2 so a single success is visible as "not yet enough".
    let mut cfg = vless_xhttp_primary();
    let mut fb = ws_fallback();
    fb.tcp_mode = TransportMode::WsH3;
    cfg.fallbacks = vec![fb];
    let mut probe = probe_cfg_for_wire_probe();
    probe.min_failures = 2;
    let manager =
        UplinkManager::new_for_test("test", vec![cfg], probe, lb_for_wire_probe()).unwrap();

    probe_cycle(&manager, false, false).await; // cap -> ws_h2
    probe_cycle(&manager, true, true).await; // one success banked at ws_h2
    probe_cycle(&manager, false, false).await; // ws_h2 breaks again
    probe_cycle(&manager, false, false).await; // streak reaches min -> ws_h1
    assert_eq!(manager.effective_tcp_mode_for_wire(0, 1).await, TransportMode::WsH1);

    // The success banked before the descent must not count toward walking
    // the *new* cap up: the descent invalidated its premise.
    probe_cycle(&manager, true, true).await;
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH1,
        "a pre-descent success must not count toward walking the new cap up",
    );
}
