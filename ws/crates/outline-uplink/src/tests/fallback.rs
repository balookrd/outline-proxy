//! Pure data-shape tests for `FallbackTransport` helpers and
//! `UplinkConfig::supports_udp_any`.
//!
//! Dial-loop integration is exercised end-to-end at the proxy crate
//! layer (where the network primitives live); these tests pin the
//! public-API contract on the fallback runtime types so downstream
//! callers can rely on it without spinning up sockets.

use url::Url;

use crate::config::{
    CipherKind, FallbackTransport, TransportMode, UplinkConfig, UplinkTransport,
};

fn vless_xhttp_primary() -> UplinkConfig {
    UplinkConfig {
        name: "edge".to_string(),
        transport: UplinkTransport::Vless,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: Some(Url::parse("https://cdn.example.com/SECRET/xhttp").unwrap()),
        vless_mode: TransportMode::XhttpH3,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: Some([0u8; 16]),
        fingerprint_profile: None,
        fallbacks: Vec::new(),
    }
}

/// Shadowsocks primary configured WITHOUT a UDP address — actually
/// `supports_udp() == false`. Used by the `supports_udp_any` tests
/// to verify that a UDP-capable fallback re-enables UDP candidacy.
fn ss_tcp_only_primary() -> UplinkConfig {
    UplinkConfig {
        name: "edge".to_string(),
        transport: UplinkTransport::Shadowsocks,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: Some("1.2.3.4:8388".parse().unwrap()),
        udp_addr: None, // <-- no UDP on primary
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
    }
}

fn ws_fallback(udp: bool) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://ws.example.com/tcp").unwrap()),
        tcp_mode: TransportMode::WsH2,
        udp_ws_url: if udp {
            Some(Url::parse("wss://ws.example.com/udp").unwrap())
        } else {
            None
        },
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        vless_id: None,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

fn ss_fallback(udp: bool) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Shadowsocks,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        vless_id: None,
        tcp_addr: Some("1.2.3.4:8388".parse().unwrap()),
        udp_addr: if udp { Some("1.2.3.4:8389".parse().unwrap()) } else { None },
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

#[test]
fn ws_fallback_dial_url_picks_tcp_url_for_tcp() {
    let fb = ws_fallback(true);
    let url = fb.tcp_dial_url().unwrap();
    assert_eq!(url.as_str(), "wss://ws.example.com/tcp");
    assert_eq!(fb.tcp_dial_mode(), TransportMode::WsH2);
}

#[test]
fn ws_fallback_dial_url_picks_udp_url_for_udp() {
    let fb = ws_fallback(true);
    let url = fb.udp_dial_url().unwrap();
    assert_eq!(url.as_str(), "wss://ws.example.com/udp");
    assert_eq!(fb.udp_dial_mode(), TransportMode::WsH1);
}

#[test]
fn ws_fallback_supports_udp_only_when_udp_url_set() {
    assert!(ws_fallback(true).supports_udp());
    assert!(!ws_fallback(false).supports_udp());
}

#[test]
fn ss_fallback_no_dial_url_but_supports_udp_via_addr() {
    let fb = ss_fallback(true);
    assert!(fb.tcp_dial_url().is_none(), "SS fallback has no WS URL");
    assert!(fb.udp_dial_url().is_none());
    assert!(fb.supports_udp(), "SS fallback supports UDP via udp_addr");
    assert!(!ss_fallback(false).supports_udp());
}

#[test]
fn vless_fallback_xhttp_mode_uses_xhttp_url() {
    let fb = FallbackTransport {
        transport: UplinkTransport::Vless,
        vless_xhttp_url: Some(Url::parse("https://cdn.example.com/x").unwrap()),
        vless_ws_url: Some(Url::parse("wss://other.example.com/ws").unwrap()),
        vless_mode: TransportMode::XhttpH2,
        vless_id: Some([1u8; 16]),
        ..ws_fallback(false)
    };
    let url = fb.tcp_dial_url().unwrap();
    assert_eq!(url.as_str(), "https://cdn.example.com/x");
    let url = fb.udp_dial_url().unwrap();
    assert_eq!(url.as_str(), "https://cdn.example.com/x");
}

#[test]
fn vless_fallback_ws_mode_uses_ws_url() {
    let fb = FallbackTransport {
        transport: UplinkTransport::Vless,
        vless_xhttp_url: Some(Url::parse("https://cdn.example.com/x").unwrap()),
        vless_ws_url: Some(Url::parse("wss://other.example.com/ws").unwrap()),
        vless_mode: TransportMode::WsH2,
        vless_id: Some([1u8; 16]),
        ..ws_fallback(false)
    };
    let url = fb.tcp_dial_url().unwrap();
    assert_eq!(url.as_str(), "wss://other.example.com/ws");
}

// ── supports_udp_any ─────────────────────────────────────────────────────────

#[test]
fn supports_udp_any_returns_true_when_primary_supports_udp() {
    let mut cfg = vless_xhttp_primary();
    // VLESS-XHTTP TCP-style only (XHTTP doesn't carry UDP) — mark as ws-mode
    // so primary supports UDP via the same URL.
    cfg.vless_mode = TransportMode::WsH2;
    cfg.vless_ws_url = Some(Url::parse("wss://primary.example.com/ws").unwrap());
    cfg.vless_xhttp_url = None;
    assert!(cfg.supports_udp(), "primary supports UDP via vless_ws_url");
    assert!(cfg.supports_udp_any());
}

#[test]
fn supports_udp_any_returns_true_when_only_fallback_supports_udp() {
    // SS primary with no `udp_addr` is the canonical TCP-only primary
    // (VLESS-XHTTP and VLESS-WS both flip `supports_udp` true via the
    // shared dial URL because mux.cool tunnels UDP through the same
    // session).
    let primary_supports_udp = ss_tcp_only_primary().supports_udp();
    assert!(!primary_supports_udp, "SS primary without udp_addr is TCP-only");

    let mut cfg = ss_tcp_only_primary();
    cfg.fallbacks = vec![ws_fallback(true)]; // UDP-capable fallback
    assert!(!cfg.supports_udp(), "primary alone still doesn't carry UDP");
    assert!(
        cfg.supports_udp_any(),
        "fallback's UDP capability surfaces through supports_udp_any"
    );
}

#[test]
fn supports_udp_any_false_when_neither_primary_nor_fallback_supports_udp() {
    let mut cfg = ss_tcp_only_primary();
    cfg.fallbacks = vec![ws_fallback(false)]; // TCP-only fallback
    assert!(!cfg.supports_udp());
    assert!(
        !cfg.supports_udp_any(),
        "all wires are TCP-only, supports_udp_any is false"
    );
}

#[test]
fn supports_udp_any_unaffected_when_primary_already_supports_udp() {
    let mut cfg = vless_xhttp_primary();
    cfg.vless_mode = TransportMode::WsH2;
    cfg.vless_ws_url = Some(Url::parse("wss://primary.example.com/ws").unwrap());
    cfg.vless_xhttp_url = None;
    cfg.fallbacks = vec![ss_fallback(false)]; // TCP-only fallback
    assert!(cfg.supports_udp());
    assert!(
        cfg.supports_udp_any(),
        "primary's UDP support already satisfies supports_udp_any"
    );
}

// ── Active-wire state machine ────────────────────────────────────────────────
//
// These pin the per-transport sticky-fallback behaviour: `wire_dial_order`
// starts at the active wire and wraps; `record_wire_outcome` advances active
// only on consecutive failures of the active wire and only after `min_failures`
// such failures have stacked; `active_wire` snaps back to primary on auto-
// failback timer expiry.

use crate::config::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, VlessUdpMuxLimits,
    WsProbeConfig,
};
use crate::types::{TransportKind, UplinkManager};

fn make_lb(mode_downgrade_duration: std::time::Duration) -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
        sticky_ttl: std::time::Duration::from_secs(300),
        hysteresis: std::time::Duration::from_millis(50),
        failure_cooldown: std::time::Duration::from_secs(10),
        tcp_chunk0_failover_timeout: std::time::Duration::from_secs(10),
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.25,
        failure_penalty: std::time::Duration::from_millis(500),
        failure_penalty_max: std::time::Duration::from_secs(30),
        failure_penalty_halflife: std::time::Duration::from_secs(60),
        mode_downgrade_duration,
        runtime_failure_window: std::time::Duration::from_secs(60),
        global_udp_strict_health: false,
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        warm_probe_keepalive_interval: None,
        auto_failback: false,
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
    }
}

fn make_probe(min_failures: usize) -> ProbeConfig {
    ProbeConfig {
        interval: std::time::Duration::from_secs(30),
        timeout: std::time::Duration::from_secs(5),
        max_concurrent: 1,
        max_dials: 1,
        min_failures,
        attempts: 1,
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
    }
}

fn manager_with_uplink(uplink: UplinkConfig, min_failures: usize) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![uplink],
        make_probe(min_failures),
        make_lb(std::time::Duration::from_secs(60)),
    )
    .unwrap()
}

#[test]
fn wire_dial_order_starts_at_primary_when_active_is_zero() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false), ss_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);
    let order = manager.wire_dial_order(0, TransportKind::Tcp, 3);
    assert_eq!(order, vec![0, 1, 2]);
}

#[test]
fn wire_dial_order_wraps_when_active_is_a_fallback() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false), ss_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);

    // Bump active to fallback[0] (index 1) by recording a primary-wire
    // failure with min_failures=1.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 3);
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 1);

    let order = manager.wire_dial_order(0, TransportKind::Tcp, 3);
    assert_eq!(order, vec![1, 2, 0], "wraps so primary is still tried last");
}

#[test]
fn record_wire_outcome_does_not_advance_below_min_failures() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 3);

    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        0,
        "two failures on min_failures=3 must not advance active",
    );

    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        1,
        "third failure crosses the threshold",
    );
}

#[test]
fn record_wire_outcome_resets_streak_on_success() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 3);

    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, true, 2);
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        0,
        "success in the middle resets the streak so threshold is not reached",
    );
}

#[test]
fn record_wire_outcome_ignores_failures_on_non_active_wire() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false), ss_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);

    // Active stays 0 throughout — failures on wire 1 (a session-local
    // fallback churn) must not influence the sticky state.
    for _ in 0..10 {
        manager.record_wire_outcome(0, TransportKind::Tcp, 1, false, 3);
    }
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 0);
}

#[test]
fn tcp_and_udp_active_wires_advance_independently() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(true)];
    let manager = manager_with_uplink(cfg, 1);

    // Fail TCP primary once → TCP active advances.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 1);
    assert_eq!(
        manager.active_wire(0, TransportKind::Udp),
        0,
        "UDP active untouched by TCP failure",
    );

    manager.record_wire_outcome(0, TransportKind::Udp, 0, false, 2);
    assert_eq!(manager.active_wire(0, TransportKind::Udp), 1);
}

#[test]
fn active_wire_snaps_back_to_primary_on_pin_expiry() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let very_short_pin = std::time::Duration::from_millis(50);
    let manager = UplinkManager::new_for_test(
        "test",
        vec![cfg],
        make_probe(1),
        make_lb(very_short_pin),
    )
    .unwrap();

    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 1);

    std::thread::sleep(std::time::Duration::from_millis(80));
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        0,
        "expired pin snaps active back to primary",
    );
}

#[test]
fn wire_dial_order_is_singleton_when_no_fallbacks() {
    let cfg = vless_xhttp_primary();
    let manager = manager_with_uplink(cfg, 1);
    assert_eq!(manager.wire_dial_order(0, TransportKind::Tcp, 1), vec![0]);
    // Recording an outcome with total_wires=1 is a no-op.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 1);
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 0);
}

#[test]
fn record_wire_outcome_stamps_last_any_wire_success() {
    use crate::manager::status::UplinkStatus;
    use crate::selection::any_wire_recent_success;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let lb = make_lb(std::time::Duration::from_secs(60));
    let manager = UplinkManager::new_for_test(
        "test",
        vec![cfg.clone()],
        make_probe(2),
        lb.clone(),
    )
    .unwrap();

    // Before any outcome: liveness override returns false.
    let snap_initial: UplinkStatus = manager.read_status_for_test(0);
    let now = tokio::time::Instant::now();
    let uplink_handle = &manager.uplinks()[0];
    assert!(!any_wire_recent_success(
        &snap_initial,
        uplink_handle,
        TransportKind::Tcp,
        now,
        &lb,
    ));

    // After a successful primary dial: liveness override returns true.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, true, 2);
    let snap_after: UplinkStatus = manager.read_status_for_test(0);
    let now = tokio::time::Instant::now();
    assert!(any_wire_recent_success(
        &snap_after,
        uplink_handle,
        TransportKind::Tcp,
        now,
        &lb,
    ));

    // Single-wire uplink: liveness override always false (no fallbacks).
    let single_cfg = ss_tcp_only_primary();
    let single_mgr =
        UplinkManager::new_for_test("solo", vec![single_cfg], make_probe(1), lb.clone()).unwrap();
    single_mgr.record_wire_outcome(0, TransportKind::Tcp, 0, true, 1);
    let snap = single_mgr.read_status_for_test(0);
    assert!(!any_wire_recent_success(
        &snap,
        &single_mgr.uplinks()[0],
        TransportKind::Tcp,
        tokio::time::Instant::now(),
        &lb,
    ));
}
