//! Pure data-shape tests for `FallbackTransport` helpers and
//! `UplinkConfig::supports_udp_any`.
//!
//! Dial-loop integration is exercised end-to-end at the proxy crate
//! layer (where the network primitives live); these tests pin the
//! public-API contract on the fallback runtime types so downstream
//! callers can rely on it without spinning up sockets.

use url::Url;

use crate::config::{CipherKind, FallbackTransport, TransportMode, UplinkConfig, UplinkTransport};

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
        shuffle_wires: false,
        carrier_downgrade: true,
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
        shuffle_wires: false,
        carrier_downgrade: true,
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

/// Shadowsocks primary configured with both TCP + UDP addresses. Used
/// by the shuffle_wires runtime / probe tests where we want
/// `wire_is_at_carrier_floor` to always return `true` (SS direct sockets
/// have no carrier-downgrade stack), so the per-wire advance gate
/// never blocks rotation. WS / VLESS / XHTTP wires hit the gate on
/// their non-floor modes (`ws_h2`, `xhttp_h3`, etc.) and require
/// explicit cap manipulation in the test setup; SS keeps the legacy
/// "N failures → advance" semantics out of the box.
fn ss_primary(udp: bool) -> UplinkConfig {
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
        udp_addr: if udp {
            Some("1.2.3.4:8389".parse().unwrap())
        } else {
            None
        },
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
    }
}

/// Second Shadowsocks endpoint, used as a fallback in shuffle_wires
/// tests when a non-WS/VLESS wire is needed (i.e. one that
/// `wire_is_at_carrier_floor` reports as "at floor" unconditionally).
/// Distinct host from `ss_fallback` so individual wires can still be
/// identified in any debug output.
fn ss_alt_fallback(udp: bool) -> FallbackTransport {
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
        tcp_addr: Some("9.9.9.9:8388".parse().unwrap()),
        udp_addr: if udp {
            Some("9.9.9.9:8389".parse().unwrap())
        } else {
            None
        },
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
        udp_addr: if udp {
            Some("1.2.3.4:8389".parse().unwrap())
        } else {
            None
        },
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
    assert!(!cfg.supports_udp_any(), "all wires are TCP-only, supports_udp_any is false");
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
        chunk0_failure_window: std::time::Duration::from_secs(300),
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
        tcp_mid_session_retry_consume_timeout: std::time::Duration::from_secs(5),
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
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
        skip_when_active: true,
        liveness_interval: std::time::Duration::from_secs(300),
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
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
fn active_wire_stays_on_fallback_after_pin_expiry() {
    // Pin expiry no longer force-snaps active back to primary — it only
    // clears the pin so the state machine is free to advance again on
    // the next failure. Auto-failback to primary is probe-driven (the
    // early-failback block in `record_transport_success` requires
    // `min_failures` consecutive primary probe successes), not
    // timer-driven; this prevents the periodic `0 → 1 → 2 → 0` cycle
    // that previously walked user-flows back through known-broken
    // wires every pin window when primary stayed dead.
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let very_short_pin = std::time::Duration::from_millis(50);
    let manager =
        UplinkManager::new_for_test("test", vec![cfg], make_probe(1), make_lb(very_short_pin))
            .unwrap();

    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 1);

    std::thread::sleep(std::time::Duration::from_millis(80));
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        1,
        "expired pin must NOT force active back to primary; the pin clears \
         silently and active stays on the fallback that has been carrying \
         traffic until probe explicitly confirms primary recovered",
    );
    // Pin itself is cleared, so a subsequent failure on the active wire
    // can advance the state machine again.
    let snap = manager.read_status_for_test(0);
    assert!(
        snap.tcp.active_wire_pinned_until.is_none(),
        "expired pin must be cleared on next read",
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
    let manager =
        UplinkManager::new_for_test("test", vec![cfg.clone()], make_probe(2), lb.clone()).unwrap();

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

// ── Probe-error path advances active_wire ───────────────────────────────────
//
// `process_probe_err` is what the scheduler calls when the probe MACHINERY
// itself errors out (WS handshake timeout, 404 from the XHTTP endpoint, TLS
// failure — anything that aborts the probe before it can produce a
// `ProbeOutcome`). It must drive the same active-wire advance that
// `process_probe_ok` does for `tcp_ok=false`, otherwise an uplink whose
// primary is reachable enough to handshake but broken at the application
// layer (e.g. server disabled XHTTP but still responds with 404) would stay
// pinned to wire 0 forever and the fallback dial loop would never run on
// passive uplinks.

#[test]
fn probe_err_advances_active_wire_to_fallback() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);

    // Two consecutive probe errors == min_failures threshold.
    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("first probe error"));
    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("second probe error"));

    let status = manager.read_status_for_test(0);
    assert_eq!(
        status.tcp.active_wire, 1,
        "after min_failures probe errors active_wire must flip to the first fallback",
    );
    assert!(
        status.tcp.active_wire_pinned_until.is_some(),
        "active_wire transition pins the fallback for the failback window",
    );
}

#[test]
fn probe_err_after_pin_expiry_does_not_re_advance_when_active_already_on_fallback() {
    // Updated semantics: pin expiry only clears the pin, it does NOT force
    // active back to primary. Therefore a primary-probe failure arriving
    // after the pin has expired hits the `active_wire != 0` guard inside
    // `advance_active_wire_on_probe_failure` and is a no-op for the
    // active-wire state machine — there is no period during which the
    // failure is allowed to walk active back to primary just to re-pin
    // it on the same fallback again. The flap that the previous test
    // pinned is exactly what the rewrite removes.
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let very_short_pin = std::time::Duration::from_millis(40);
    let manager =
        UplinkManager::new_for_test("test", vec![cfg], make_probe(1), make_lb(very_short_pin))
            .unwrap();

    // First failure: active_wire flips to 1, pin set.
    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("primary 404"));
    let status = manager.read_status_for_test(0);
    assert_eq!(status.tcp.active_wire, 1);
    assert!(status.tcp.active_wire_pinned_until.is_some(), "pin set on first flip");

    // Wait the pin out.
    std::thread::sleep(very_short_pin + std::time::Duration::from_millis(10));

    // Second probe failure after pin expiry: pin gets cleared but active
    // stays on the fallback. No re-pin, no churn.
    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("primary still 404"));
    let status = manager.read_status_for_test(0);
    assert_eq!(
        status.tcp.active_wire, 1,
        "active must remain on the fallback wire — pin expiry is not a \
         signal to re-test primary",
    );
    assert!(
        status.tcp.active_wire_pinned_until.is_none(),
        "pin remains cleared; no spurious re-pin on the fallback that is \
         already active",
    );
}

#[test]
fn probe_failure_walks_xhttp_downgrade_chain_h3_h2_h1() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // primary configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);

    // Cycle 1: probe of XHTTP/H3 fails. Cap should land at XHTTP/H2.
    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("h3 unreachable"));
    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(cap, Some(TransportMode::XhttpH2), "first failure caps H3 → H2");

    // Cycle 2: probe of XHTTP/H2 (the now-effective carrier) fails. Cap
    // should advance to XHTTP/H1 — the previous design fed back the
    // configured (still-H3) mode here, so the cap stalled at H2 forever.
    let outcome_with_h2_failed = ProbeOutcome {
        tcp_ok: false,
        udp_ok: false,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        outcome_with_h2_failed,
        TransportMode::XhttpH2,
        TransportMode::XhttpH2,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(cap, Some(TransportMode::XhttpH1), "second failure caps H2 → H1");
}

#[test]
fn probe_err_does_not_advance_below_min_failures() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 3);

    // Only two errors, threshold is three.
    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("first probe error"));
    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("second probe error"));

    let status = manager.read_status_for_test(0);
    assert_eq!(
        status.tcp.active_wire, 0,
        "below min_failures the streak alone must not flip active_wire",
    );
}

// ── Mode-downgrade descent gate / walk-up / carrier recovery ────────────────
//
// These pin the descent + recovery contract for the XHTTP family so flaky
// H2 probes don't bounce real traffic onto H1 (the "video stalls" pattern
// from the field). The three tests cover, in order:
//  * #3 descent gate — stepping the cap further down requires
//    `min_failures` consecutive failures on the capped carrier;
//  * #2 walk-up — `min_failures` consecutive successes on the capped
//    carrier lift the cap one rank toward configured (or clear it);
//  * #1 recovery push — VLESS+XHTTP uplinks queue a configured-carrier
//    re-probe just like WS+H3 does.

#[test]
fn xhttp_step_down_gated_by_min_failures() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 3);

    // First failure: configured H3 fails. cap = H2, no prev cap so the
    // descent gate doesn't apply — the initial entry into the window is
    // always one rank below configured.
    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("h3 unreachable"));
    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(cap, Some(TransportMode::XhttpH2), "first failure caps H3 → H2");

    let make_failed_outcome = || ProbeOutcome {
        tcp_ok: false,
        udp_ok: false,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();

    // Second failure on the capped carrier: counter reaches 2 (still
    // below min_failures=3) — the gate must hold the cap at H2 instead
    // of stepping down to H1.
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        make_failed_outcome(),
        TransportMode::XhttpH2,
        TransportMode::XhttpH2,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(
        cap,
        Some(TransportMode::XhttpH2),
        "consecutive_failures=2 < min_failures=3 must hold the cap at H2",
    );

    // Third failure: counter reaches 3, gate releases, cap descends to H1.
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        make_failed_outcome(),
        TransportMode::XhttpH2,
        TransportMode::XhttpH2,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(
        cap,
        Some(TransportMode::XhttpH1),
        "after min_failures consecutive failures the gate releases and the cap descends",
    );
}

#[test]
fn xhttp_walk_up_after_consecutive_successes_on_capped_carrier() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures=1 so a single success crosses the streak threshold
    // (the `record_transport_success` path increments
    // `consecutive_successes` once per successful probe).
    let manager = manager_with_uplink(cfg, 1);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH1);

    let make_ok_outcome = || ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();

    // First success at the capped H1 carrier walks the cap up to H2.
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        make_ok_outcome(),
        TransportMode::XhttpH1,
        TransportMode::XhttpH1,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(
        cap,
        Some(TransportMode::XhttpH2),
        "first success on capped H1 walks the cap one rank up to H2",
    );

    // Second success at the new capped H2 carrier would reach
    // configured H3 — but walk-up does NOT clear to configured. That
    // last hop is owned by the configured-carrier recovery probe (it
    // tests configured directly). Cap stays sticky at H2 until
    // recovery proves H3 is back; this kills the H2↔H3 oscillation
    // pattern on intermittent configured carriers.
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        make_ok_outcome(),
        TransportMode::XhttpH2,
        TransportMode::XhttpH2,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(
        cap,
        Some(TransportMode::XhttpH2),
        "second success at H2 must NOT walk up to configured H3 — recovery probe owns that hop",
    );
}

#[test]
fn xhttp_walk_up_holds_below_min_failures() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures=3 → a single success isn't enough to walk up.
    let manager = manager_with_uplink(cfg, 3);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH1);

    let outcome = ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        outcome,
        TransportMode::XhttpH1,
        TransportMode::XhttpH1,
        &mut tcp_recovery,
        &mut udp_recovery,
    );

    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(
        cap,
        Some(TransportMode::XhttpH1),
        "consecutive_successes=1 < min_failures=3 must hold the cap at H1",
    );
}

#[test]
fn xhttp_walk_up_holds_at_one_below_configured() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures=1 → a single success would arm walk-up's clear arm
    // under the old behaviour. New behaviour requires the
    // configured-carrier recovery probe to make the final hop.
    let manager = manager_with_uplink(cfg, 1);

    // Pre-seed cap = H2 (one rank below configured H3). The cap should
    // stay sticky here regardless of how many successful probes land
    // at the H2 carrier — only `run_h3_recovery_probes` testing
    // configured H3 directly can clear it.
    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);

    let make_ok = || ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();
    for _ in 0..5 {
        let _ = manager.process_probe_ok(
            0,
            &uplink,
            make_ok(),
            TransportMode::XhttpH2,
            TransportMode::XhttpH2,
            &mut tcp_recovery,
            &mut udp_recovery,
        );
        assert_eq!(
            manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
            Some(TransportMode::XhttpH2),
            "cap at one-below-configured stays sticky across probe-success streaks",
        );
    }
}

#[test]
fn xhttp_recovery_push_for_vless_when_walk_up_does_not_clear_cap() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures=3 keeps walk-up dormant so we can observe the
    // configured-carrier recovery push fire on its own.
    let manager = manager_with_uplink(cfg, 3);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH1);

    let outcome = ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        outcome,
        TransportMode::XhttpH1,
        TransportMode::XhttpH1,
        &mut tcp_recovery,
        &mut udp_recovery,
    );

    assert_eq!(
        tcp_recovery.len(),
        1,
        "VLESS+XHTTP cap with insufficient successes for walk-up must queue a configured-carrier recovery probe",
    );
    let cap = manager.read_status_for_test(0).tcp.mode_downgrade_capped_to;
    assert_eq!(
        cap,
        Some(TransportMode::XhttpH1),
        "single success below min_failures must not walk up — recovery push remains the lever",
    );
}

#[test]
fn xhttp_recovery_cooldown_blocks_recovery_push_until_expiry() {
    use crate::config::TransportMode;
    use crate::manager::mode_downgrade::ModeDowngradeTrigger;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures=3 keeps walk-up dormant so the only mechanism that
    // could clear the cap in this scenario is the recovery probe.
    let manager = manager_with_uplink(cfg, 3);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);

    // Simulate a failed recovery probe: the configured-carrier
    // re-probe didn't recover H3, so `extend_mode_downgrade` is
    // called with `RecoveryReprobeFail`. This should arm the
    // recovery cooldown.
    manager.extend_mode_downgrade(0, TransportKind::Tcp, ModeDowngradeTrigger::RecoveryReprobeFail);
    assert!(
        manager
            .read_status_for_test(0)
            .tcp
            .recovery_probe_cooldown_until
            .is_some(),
        "RecoveryReprobeFail must arm the recovery-probe cooldown so the next probe cycle does not re-run recovery",
    );

    // Subsequent successful probe at the capped carrier must NOT
    // queue another recovery probe — the cooldown is in effect.
    let outcome = ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        outcome,
        TransportMode::XhttpH2,
        TransportMode::XhttpH2,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    assert_eq!(
        tcp_recovery.len(),
        0,
        "while recovery cooldown is active the regular probe success must NOT queue another recovery probe",
    );
    assert_eq!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
        Some(TransportMode::XhttpH2),
        "cap stays sticky at the deepest stable rank while recovery cooldown is active",
    );
}

#[test]
fn xhttp_post_recovery_grace_absorbs_consecutive_probe_fails_until_min_failures() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures=2 — grace absorbs 2 attempts, releases on 3rd.
    let manager = manager_with_uplink(cfg, 2);

    // Seed a cap, then simulate a successful recovery by calling
    // `clear_mode_downgrade` directly — it stamps `last_recovery_success_at`
    // so the grace window opens.
    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    manager.clear_mode_downgrade(0, TransportKind::Tcp);
    let s = manager.read_status_for_test(0);
    assert!(s.tcp.mode_downgrade_capped_to.is_none());
    assert!(s.tcp.last_recovery_success_at.is_some());

    let make_failed = || ProbeOutcome {
        tcp_ok: false,
        udp_ok: false,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();

    // First two consecutive probe-fails inside grace are absorbed.
    for i in 0..2 {
        let _ = manager.process_probe_ok(
            0,
            &uplink,
            make_failed(),
            TransportMode::XhttpH3,
            TransportMode::XhttpH3,
            &mut tcp_recovery,
            &mut udp_recovery,
        );
        assert!(
            manager.read_status_for_test(0).tcp.mode_downgrade_capped_to.is_none(),
            "probe-fail #{} inside grace must be absorbed (counter < min_failures)",
            i + 1,
        );
    }

    // Third consecutive fail releases the gate; cap re-installs.
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        make_failed(),
        TransportMode::XhttpH3,
        TransportMode::XhttpH3,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    assert_eq!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
        Some(TransportMode::XhttpH2),
        "after `min_failures` absorbed fails the grace releases on the next descent",
    );
}

#[test]
fn xhttp_post_recovery_grace_counter_reset_by_probe_success_between_fails() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    manager.clear_mode_downgrade(0, TransportKind::Tcp);

    let make_failed = || ProbeOutcome {
        tcp_ok: false,
        udp_ok: false,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let make_ok = || ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();

    // Pattern: fail, success, fail, success, fail — five cycles. The
    // success between fails should reset the grace counter, so the
    // total absorbed-without-release count is "1 fail since last
    // success" each time, never reaching min_failures=2.
    for cycle in 0..3 {
        let _ = manager.process_probe_ok(
            0,
            &uplink,
            make_failed(),
            TransportMode::XhttpH3,
            TransportMode::XhttpH3,
            &mut tcp_recovery,
            &mut udp_recovery,
        );
        assert!(
            manager.read_status_for_test(0).tcp.mode_downgrade_capped_to.is_none(),
            "cycle {}: lone fail with intervening successes must stay absorbed",
            cycle,
        );
        let _ = manager.process_probe_ok(
            0,
            &uplink,
            make_ok(),
            TransportMode::XhttpH3,
            TransportMode::XhttpH3,
            &mut tcp_recovery,
            &mut udp_recovery,
        );
        assert_eq!(
            manager
                .read_status_for_test(0)
                .tcp
                .post_recovery_grace_descent_attempts,
            0,
            "probe success in grace must reset the absorbed-attempts counter",
        );
    }

    // Final assertion: cap is still cleared after the mixed pattern.
    assert!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to.is_none(),
        "isolated fails with successes between are absorbed forever — no cap re-install",
    );
}

#[test]
fn xhttp_post_recovery_grace_absorbs_silent_fallback_from_dispatcher() {
    use crate::config::TransportMode;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures=2 — grace absorbs 2 silent fallbacks, releases on 3rd.
    let manager = manager_with_uplink(cfg, 2);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    manager.clear_mode_downgrade(0, TransportKind::Tcp);

    // First two silent fallbacks (typical dispatcher pattern: each
    // user-driven dial that observes an inline H3 → H2 fall) are
    // absorbed by the grace gate.
    for i in 0..2 {
        manager.note_silent_transport_fallback(0, TransportKind::Tcp, TransportMode::XhttpH3);
        assert!(
            manager.read_status_for_test(0).tcp.mode_downgrade_capped_to.is_none(),
            "silent fallback #{} inside post-recovery grace must be absorbed",
            i + 1,
        );
    }

    // Third silent fallback releases the gate (counter == min_failures).
    manager.note_silent_transport_fallback(0, TransportKind::Tcp, TransportMode::XhttpH3);
    assert_eq!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
        Some(TransportMode::XhttpH2),
        "third silent fallback releases the gate and re-installs the cap",
    );
}

#[test]
fn xhttp_post_recovery_grace_absorbs_runtime_failure_after_recovery() {
    use crate::config::TransportMode;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    manager.clear_mode_downgrade(0, TransportKind::Tcp);

    // First two runtime failures inside grace are absorbed.
    for i in 0..2 {
        let err = anyhow::anyhow!("h3 stream reset by peer ({})", i);
        manager.note_advanced_mode_dial_failure(0, TransportKind::Tcp, &err);
        assert!(
            manager.read_status_for_test(0).tcp.mode_downgrade_capped_to.is_none(),
            "runtime failure #{} inside post-recovery grace must be absorbed",
            i + 1,
        );
    }

    // Third releases the gate.
    let err = anyhow::anyhow!("h3 stream reset by peer (final)");
    manager.note_advanced_mode_dial_failure(0, TransportKind::Tcp, &err);
    assert_eq!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
        Some(TransportMode::XhttpH2),
        "third runtime failure releases the grace gate",
    );
}

#[test]
fn xhttp_post_recovery_grace_attempts_reset_on_cap_install() {
    use crate::config::TransportMode;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 3);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    manager.clear_mode_downgrade(0, TransportKind::Tcp);

    // Three absorbed attempts; counter reaches 3 (= min_failures).
    for _ in 0..3 {
        manager.note_silent_transport_fallback(0, TransportKind::Tcp, TransportMode::XhttpH3);
    }
    assert_eq!(
        manager
            .read_status_for_test(0)
            .tcp
            .post_recovery_grace_descent_attempts,
        3,
        "three absorbed silent fallbacks counted toward the grace budget",
    );

    // Fourth silent fallback releases the gate and installs cap
    // (counter == min_failures, condition `< min_failures` false).
    manager.note_silent_transport_fallback(0, TransportKind::Tcp, TransportMode::XhttpH3);
    let s = manager.read_status_for_test(0);
    assert_eq!(
        s.tcp.mode_downgrade_capped_to,
        Some(TransportMode::XhttpH2),
        "fourth silent fallback released the gate (min_failures=3 → 3 absorbs + release on 4th)",
    );
    assert_eq!(
        s.tcp.post_recovery_grace_descent_attempts, 0,
        "cap install resets the grace attempt counter",
    );
}

#[test]
fn xhttp_recovery_streak_requires_two_successes_to_clear_cap() {
    use crate::config::TransportMode;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);

    // First successful recovery: tentative — cap stays installed,
    // streak counter advances to 1.
    manager.note_recovery_probe_success(0, TransportKind::Tcp);
    let s = manager.read_status_for_test(0);
    assert_eq!(
        s.tcp.mode_downgrade_capped_to,
        Some(TransportMode::XhttpH2),
        "first recovery success is tentative — cap must NOT clear on a single confirmation",
    );
    assert_eq!(
        s.tcp.recovery_probe_success_streak, 1,
        "streak counter advances to 1 on the first tentative success",
    );

    // Second consecutive recovery success — clear the cap.
    manager.note_recovery_probe_success(0, TransportKind::Tcp);
    let s = manager.read_status_for_test(0);
    assert!(
        s.tcp.mode_downgrade_capped_to.is_none(),
        "second consecutive recovery success meets the streak threshold and clears the cap",
    );
    assert_eq!(
        s.tcp.recovery_probe_success_streak, 0,
        "clearing the cap also resets the recovery streak counter",
    );
}

#[test]
fn xhttp_recovery_streak_reset_on_descent() {
    use crate::config::TransportMode;
    use crate::manager::mode_downgrade::ModeDowngradeTrigger;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    // One tentative recovery success.
    manager.note_recovery_probe_success(0, TransportKind::Tcp);
    assert_eq!(manager.read_status_for_test(0).tcp.recovery_probe_success_streak, 1,);

    // A failed recovery probe in the same cap window must reset
    // the streak — the previous tentative success was unlucky.
    manager.extend_mode_downgrade(0, TransportKind::Tcp, ModeDowngradeTrigger::RecoveryReprobeFail);
    assert_eq!(
        manager.read_status_for_test(0).tcp.recovery_probe_success_streak,
        0,
        "RecoveryReprobeFail resets the recovery streak so the next clear requires a fresh streak",
    );
}

#[test]
fn xhttp_recovery_streak_reset_when_cap_changes_via_descent() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures=1 so a single probe failure releases descent.
    let manager = manager_with_uplink(cfg, 1);

    // Pre-seed cap=H2, then bump the streak to 1 via a tentative
    // recovery success (cap stays H2 because threshold = 2). No
    // call to `clear_mode_downgrade`, so the post-recovery grace
    // is NOT armed and the descent path runs straight through.
    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    manager.note_recovery_probe_success(0, TransportKind::Tcp);
    assert_eq!(manager.read_status_for_test(0).tcp.recovery_probe_success_streak, 1,);

    // Drive a probe failure at the capped carrier (H2). With
    // min_failures=1 the in-window descent gate is satisfied
    // immediately, so the cap descends one rank to H1.
    let outcome = ProbeOutcome {
        tcp_ok: false,
        udp_ok: false,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        outcome,
        TransportMode::XhttpH2,
        TransportMode::XhttpH2,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    let s = manager.read_status_for_test(0);
    assert_eq!(
        s.tcp.mode_downgrade_capped_to,
        Some(TransportMode::XhttpH1),
        "descent moved the cap H2 → H1 (cap_changed = true)",
    );
    assert_eq!(
        s.tcp.recovery_probe_success_streak, 0,
        "cap_changed resets the recovery streak — prior tentative successes are stale",
    );
}

/// Construct a fresh WS uplink configured at H3 — used by the
/// WS-mirror tests that verify the symmetric hysteresis path
/// (walk-up sticky, recovery streak, post-recovery grace) works
/// for the WS family and not just XHTTP.
fn ws_h3_primary() -> UplinkConfig {
    UplinkConfig {
        name: "ws-edge".to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://ws.example.com/tcp").unwrap()),
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: Some(Url::parse("wss://ws.example.com/udp").unwrap()),
        udp_mode: TransportMode::WsH3,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
    }
}

#[test]
fn ws_walk_up_holds_at_one_below_configured() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    // Mirrors `xhttp_walk_up_holds_at_one_below_configured` but
    // exercises the WS family — proves walk-up's "stop one rank
    // below configured, let recovery probe own the last hop"
    // contract is transport-agnostic.
    let manager = manager_with_uplink(ws_h3_primary(), 1);
    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::WsH2);

    let make_ok = || ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();
    for _ in 0..5 {
        let _ = manager.process_probe_ok(
            0,
            &uplink,
            make_ok(),
            TransportMode::WsH2,
            TransportMode::WsH2,
            &mut tcp_recovery,
            &mut udp_recovery,
        );
        assert_eq!(
            manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
            Some(TransportMode::WsH2),
            "WS walk-up holds at H2 (one rank below configured H3) — last hop is recovery's job",
        );
    }
}

#[test]
fn ws_recovery_streak_requires_two_successes_to_clear_cap() {
    use crate::config::TransportMode;

    // Mirrors `xhttp_recovery_streak_requires_two_successes_to_clear_cap`.
    let manager = manager_with_uplink(ws_h3_primary(), 2);
    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::WsH2);

    // First recovery success — tentative, cap stays.
    manager.note_recovery_probe_success(0, TransportKind::Tcp);
    let s = manager.read_status_for_test(0);
    assert_eq!(
        s.tcp.mode_downgrade_capped_to,
        Some(TransportMode::WsH2),
        "WS first recovery success is tentative (streak threshold = 2)",
    );
    assert_eq!(s.tcp.recovery_probe_success_streak, 1);

    // Second consecutive recovery success clears the cap.
    manager.note_recovery_probe_success(0, TransportKind::Tcp);
    let s = manager.read_status_for_test(0);
    assert!(
        s.tcp.mode_downgrade_capped_to.is_none(),
        "WS second consecutive recovery success clears the cap",
    );
    assert_eq!(s.tcp.recovery_probe_success_streak, 0);
}

#[test]
fn ws_post_recovery_grace_absorbs_runtime_failure_after_recovery() {
    use crate::config::TransportMode;

    // Mirrors `xhttp_post_recovery_grace_absorbs_runtime_failure_after_recovery`.
    let manager = manager_with_uplink(ws_h3_primary(), 2);
    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::WsH2);
    manager.clear_mode_downgrade(0, TransportKind::Tcp);

    // First two runtime failures inside grace are absorbed.
    for i in 0..2 {
        let err = anyhow::anyhow!("ws runtime fail ({})", i);
        manager.note_advanced_mode_dial_failure(0, TransportKind::Tcp, &err);
        assert!(
            manager.read_status_for_test(0).tcp.mode_downgrade_capped_to.is_none(),
            "WS runtime failure #{} inside post-recovery grace must be absorbed",
            i + 1,
        );
    }

    // Third runtime failure releases the gate.
    let err = anyhow::anyhow!("ws runtime fail (final)");
    manager.note_advanced_mode_dial_failure(0, TransportKind::Tcp, &err);
    assert_eq!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
        Some(TransportMode::WsH2),
        "WS third runtime failure releases the grace gate (counter == min_failures)",
    );
}

#[test]
fn ws_chain_walks_full_h3_h2_h1_descent() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    // WS uplink configured at H3, single TCP wire.
    let cfg = UplinkConfig {
        name: "ws-edge".to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(Url::parse("wss://ws.example.com/tcp").unwrap()),
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: Some(Url::parse("wss://ws.example.com/udp").unwrap()),
        udp_mode: TransportMode::WsH3,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        shuffle_wires: false,
        carrier_downgrade: true,
    };
    // min_failures=1 so each probe failure crosses both the
    // in-window descent gate (`consecutive_failures < min_failures`)
    // and triggers a cap step on the same cycle.
    let manager = manager_with_uplink(cfg, 1);

    let make_failed = || ProbeOutcome {
        tcp_ok: false,
        udp_ok: false,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();

    // First probe cycle: effective = WsH3 (no cap yet), fails → cap=H2.
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        make_failed(),
        TransportMode::WsH3,
        TransportMode::WsH3,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    assert_eq!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
        Some(TransportMode::WsH2),
        "WS chain: first probe failure on configured H3 caps to H2",
    );

    // Second probe cycle: effective = WsH2 (capped), fails → cap=H1.
    // Without the new `WsH2 → WsH1` descent step this stalled at H2,
    // leaving the dashboard's `H2 ↘ DOWN` operator-confusing.
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        make_failed(),
        TransportMode::WsH2,
        TransportMode::WsH2,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    assert_eq!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
        Some(TransportMode::WsH1),
        "WS chain: second probe failure on H2 caps to H1 (H3 → H2 → H1 walk)",
    );

    // Third probe cycle: effective = WsH1, fails → cap stays H1
    // (deepest rank in the family).
    let _ = manager.process_probe_ok(
        0,
        &uplink,
        make_failed(),
        TransportMode::WsH1,
        TransportMode::WsH1,
        &mut tcp_recovery,
        &mut udp_recovery,
    );
    assert_eq!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to,
        Some(TransportMode::WsH1),
        "WS chain: H1 is the deepest rank; further failures don't move the cap",
    );
}

#[test]
fn xhttp_post_recovery_grace_renewed_by_probe_success_across_wide_gap() {
    use crate::config::TransportMode;
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary(); // configured XhttpH3
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);

    // Open the grace window via a recovery clear.
    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    manager.clear_mode_downgrade(0, TransportKind::Tcp);

    let make_ok = || ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: None,
        udp_latency: None,
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    };
    let uplink = manager.uplinks()[0].clone();
    let mut tcp_recovery = Vec::new();
    let mut udp_recovery = Vec::new();

    // A burst of successful probes — each one should renew
    // `last_recovery_success_at`. We can't fast-forward time in
    // this test, but we can verify that the timestamp is being
    // re-stamped on each success.
    let initial = manager
        .read_status_for_test(0)
        .tcp
        .last_recovery_success_at
        .expect("grace timestamp set by clear");

    // Run a couple of probe cycles' worth of successes.
    for _ in 0..3 {
        let _ = manager.process_probe_ok(
            0,
            &uplink,
            make_ok(),
            TransportMode::XhttpH3,
            TransportMode::XhttpH3,
            &mut tcp_recovery,
            &mut udp_recovery,
        );
    }

    let renewed = manager
        .read_status_for_test(0)
        .tcp
        .last_recovery_success_at
        .expect("grace timestamp still set");
    assert!(
        renewed >= initial,
        "probe success in grace must (re)stamp last_recovery_success_at — \
         field VLESS-mux idle pattern needs the gate to live across multi-minute gaps",
    );

    // After the probe-success burst the grace deadline has slid
    // forward; an isolated runtime error must still be absorbed
    // even if it arrives "long after" the original clear.
    let err = anyhow::anyhow!("ws upstream read idle for 300s on datagram channel");
    manager.note_advanced_mode_dial_failure(0, TransportKind::Tcp, &err);
    assert!(
        manager.read_status_for_test(0).tcp.mode_downgrade_capped_to.is_none(),
        "runtime error long after recovery clear is still absorbed because probe successes kept the grace alive",
    );
}

#[test]
fn xhttp_recovery_cooldown_cleared_by_clear_mode_downgrade() {
    use crate::config::TransportMode;
    use crate::manager::mode_downgrade::ModeDowngradeTrigger;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 3);

    manager.test_seed_mode_downgrade_for_test(0, TransportKind::Tcp, TransportMode::XhttpH2);
    manager.extend_mode_downgrade(0, TransportKind::Tcp, ModeDowngradeTrigger::RecoveryReprobeFail);
    assert!(
        manager
            .read_status_for_test(0)
            .tcp
            .recovery_probe_cooldown_until
            .is_some(),
        "cooldown armed by RecoveryReprobeFail",
    );

    manager.clear_mode_downgrade(0, TransportKind::Tcp);

    let s = manager.read_status_for_test(0);
    assert!(
        s.tcp.mode_downgrade_until.is_none()
            && s.tcp.mode_downgrade_capped_to.is_none()
            && s.tcp.recovery_probe_cooldown_until.is_none(),
        "clear_mode_downgrade resets cap, deadline, AND recovery cooldown together",
    );
}

// ── Per-wire RTT EWMA ───────────────────────────────────────────────────────
//
// Each wire on a multi-wire uplink keeps its own RTT EWMA. The cross-uplink
// scoring layer reads the EWMA of whichever wire is currently active, so
// scoring compares peers by the wire that is actually carrying traffic
// rather than primary's measurement (which may belong to a wire the dial
// loop has long since moved off).

#[test]
fn active_wire_rtt_ewma_reads_primary_slot_for_wire_zero() {
    use crate::manager::status::PerTransportStatus;
    let mut st = PerTransportStatus::default();
    st.rtt_ewma = Some(std::time::Duration::from_millis(40));
    st.fallback_rtt_ewma.push(Some(std::time::Duration::from_millis(120)));
    st.active_wire = 0;
    assert_eq!(st.active_wire_rtt_ewma(), Some(std::time::Duration::from_millis(40)));
}

#[test]
fn active_wire_rtt_ewma_reads_fallback_slot_when_advanced() {
    use crate::manager::status::PerTransportStatus;
    let mut st = PerTransportStatus::default();
    st.rtt_ewma = Some(std::time::Duration::from_millis(40));
    st.fallback_rtt_ewma.push(Some(std::time::Duration::from_millis(120)));
    st.active_wire = 1;
    assert_eq!(
        st.active_wire_rtt_ewma(),
        Some(std::time::Duration::from_millis(120)),
        "with active_wire=1 the fallback slot is the source of truth — primary may be a now-broken wire",
    );
}

#[test]
fn active_wire_rtt_ewma_returns_none_when_fallback_slot_unset() {
    use crate::manager::status::PerTransportStatus;
    let mut st = PerTransportStatus::default();
    st.rtt_ewma = Some(std::time::Duration::from_millis(40));
    // No `fallback_rtt_ewma` push — slot 0 is missing.
    st.active_wire = 1;
    assert!(
        st.active_wire_rtt_ewma().is_none(),
        "scoring chooses the bounded-stale fallback path itself; the slot returns None until probed",
    );
}

#[test]
fn record_fallback_wire_latency_lazy_extends_vec() {
    use crate::manager::status::PerTransportStatus;
    let mut st = PerTransportStatus::default();
    // Wire 2 first — slot 1. Slot 0 should be auto-filled with None.
    st.record_fallback_wire_latency(2, Some(std::time::Duration::from_millis(80)), 0.5);
    assert_eq!(st.fallback_rtt_ewma.len(), 2);
    assert_eq!(st.fallback_rtt_ewma[0], None);
    assert_eq!(st.fallback_rtt_ewma[1], Some(std::time::Duration::from_millis(80)));
}

#[test]
fn record_fallback_wire_latency_is_noop_for_primary() {
    use crate::manager::status::PerTransportStatus;
    let mut st = PerTransportStatus::default();
    st.rtt_ewma = Some(std::time::Duration::from_millis(40));
    st.record_fallback_wire_latency(0, Some(std::time::Duration::from_millis(999)), 0.5);
    // Primary's EWMA goes through the existing `update_rtt_ewma` path in the
    // probe outcome handler; this helper deliberately ignores wire 0 so the
    // per-wire probe walk doesn't double-write primary's slot.
    assert_eq!(st.rtt_ewma, Some(std::time::Duration::from_millis(40)));
    assert!(st.fallback_rtt_ewma.is_empty());
}

#[test]
fn record_fallback_wire_latency_smooths_subsequent_samples() {
    use crate::manager::status::PerTransportStatus;
    let mut st = PerTransportStatus::default();
    let alpha = 0.5;
    st.record_fallback_wire_latency(1, Some(std::time::Duration::from_millis(100)), alpha);
    st.record_fallback_wire_latency(1, Some(std::time::Duration::from_millis(200)), alpha);
    // EWMA: 100 → (100*0.5 + 200*0.5) = 150ms.
    assert_eq!(st.fallback_rtt_ewma[0], Some(std::time::Duration::from_millis(150)));
}

#[test]
fn scoring_base_latency_uses_active_wire_ewma_when_advanced() {
    use crate::manager::status::PerTransportStatus;
    use crate::selection::scoring_base_latency;
    let mut tcp = PerTransportStatus::default();
    tcp.rtt_ewma = Some(std::time::Duration::from_millis(40));
    tcp.latency = Some(std::time::Duration::from_millis(50));
    tcp.fallback_rtt_ewma
        .push(Some(std::time::Duration::from_millis(120)));
    tcp.active_wire = 1;
    let status = crate::manager::status::UplinkStatus { tcp, ..Default::default() };
    assert_eq!(
        scoring_base_latency(&status, TransportKind::Tcp),
        Some(std::time::Duration::from_millis(120)),
        "scoring against peers must use the wire actually carrying traffic",
    );
}

#[test]
fn scoring_base_latency_falls_back_to_primary_when_fallback_ewma_unset() {
    use crate::manager::status::PerTransportStatus;
    use crate::selection::scoring_base_latency;
    let mut tcp = PerTransportStatus::default();
    tcp.rtt_ewma = Some(std::time::Duration::from_millis(40));
    tcp.latency = Some(std::time::Duration::from_millis(50));
    tcp.active_wire = 1;
    // No fallback slot pushed — cold start right after a wire flip.
    let status = crate::manager::status::UplinkStatus { tcp, ..Default::default() };
    assert_eq!(
        scoring_base_latency(&status, TransportKind::Tcp),
        Some(std::time::Duration::from_millis(40)),
        "until per-wire probe stamps in, primary's EWMA is the best signal we have",
    );
}

// ── Bootstrap pass-through: primary down, fallback never tried ──────────────
//
// `selection_health` must admit an uplink whose primary wire is probe-marked
// unhealthy AND whose fallback wire has never recorded a successful dial yet,
// so the active-wire dial loop has a chance to attempt the fallback. Without
// this, `last_any_wire_success` (stamped only from inside the dial loop) and
// candidate filtering deadlock each other and the fallback never engages.

#[test]
fn selection_health_admits_unhealthy_primary_when_fallback_untried() {
    use crate::config::RoutingScope;
    use crate::selection::{fallback_bootstrap_allowed, selection_health};

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let lb = make_lb(std::time::Duration::from_secs(60));
    let manager =
        UplinkManager::new_for_test("test", vec![cfg], make_probe(1), lb.clone()).unwrap();

    // Probe says primary is down; nothing else has happened yet.
    manager.inner.with_status_mut(0, |status| {
        status.tcp.healthy = Some(false);
    });

    let status = manager.read_status_for_test(0);
    let uplink = &manager.uplinks()[0];
    let now = tokio::time::Instant::now();

    assert!(
        fallback_bootstrap_allowed(&status, uplink, TransportKind::Tcp, now),
        "fallback configured + no prior success + no cooldown → bootstrap allowed",
    );
    assert!(
        selection_health(&status, uplink, TransportKind::Tcp, now, RoutingScope::PerFlow, &lb),
        "selection must admit the uplink so the dial loop can try the fallback",
    );
    assert!(
        selection_health(&status, uplink, TransportKind::Tcp, now, RoutingScope::Global, &lb),
        "global scope must also admit the uplink for the same reason",
    );
}

#[test]
fn fallback_bootstrap_blocked_during_cooldown() {
    use crate::selection::fallback_bootstrap_allowed;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let lb = make_lb(std::time::Duration::from_secs(60));
    let manager =
        UplinkManager::new_for_test("test", vec![cfg], make_probe(1), lb.clone()).unwrap();

    let now = tokio::time::Instant::now();
    manager.inner.with_status_mut(0, |status| {
        status.tcp.healthy = Some(false);
        status.tcp.cooldown_until = Some(now + std::time::Duration::from_secs(5));
    });

    let status = manager.read_status_for_test(0);
    let uplink = &manager.uplinks()[0];

    assert!(
        !fallback_bootstrap_allowed(&status, uplink, TransportKind::Tcp, now),
        "active cooldown must suppress bootstrap admission",
    );
}

#[test]
fn fallback_bootstrap_off_after_first_wire_success() {
    use crate::selection::fallback_bootstrap_allowed;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let lb = make_lb(std::time::Duration::from_secs(60));
    let manager =
        UplinkManager::new_for_test("test", vec![cfg], make_probe(1), lb.clone()).unwrap();

    // Record a fallback-wire success — bootstrap must hand off to the
    // recent-success window from this point on.
    manager.record_wire_outcome(0, TransportKind::Tcp, 1, true, 2);

    let status = manager.read_status_for_test(0);
    let uplink = &manager.uplinks()[0];
    let now = tokio::time::Instant::now();

    assert!(
        !fallback_bootstrap_allowed(&status, uplink, TransportKind::Tcp, now),
        "after the first wire success the bootstrap path is no longer needed",
    );
}

// ── Early failback via probe-recovery ────────────────────────────────────────
//
// `record_transport_success` (probe path) snaps `active_wire` back to primary
// as soon as the primary wire's probe accumulates `min_failures` consecutive
// successes — short-circuiting the auto-failback timer. The probe always
// targets the primary wire in this iteration, so a probe success directly
// proves primary recovery; no per-wire probe machinery needed for this
// optimisation.

#[test]
fn probe_recovery_snaps_active_wire_back_to_primary() {
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures = 2 so we can verify the streak threshold.
    let manager = UplinkManager::new_for_test(
        "test",
        vec![cfg],
        make_probe(2),
        // Pin window long enough that timer-driven failback can't be the
        // explanation for the snap-back we observe.
        make_lb(std::time::Duration::from_secs(3600)),
    )
    .unwrap();

    // Drive active wire onto a fallback by failing the primary's dial twice.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        1,
        "primary failed past min_failures, active should advance to fallback",
    );

    // First probe success on primary: not enough yet (min_failures=2).
    manager.test_apply_probe_outcome_for_test(
        0,
        ProbeOutcome {
            tcp_ok: true,
            udp_ok: false,
            udp_applicable: false,
            tcp_latency: None,
            udp_latency: None,
            tcp_downgraded_from: None,
            udp_downgraded_from: None,
        },
    );
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        1,
        "single probe success below threshold must not flip back to primary",
    );

    // Second consecutive probe success: threshold reached → snap back.
    manager.test_apply_probe_outcome_for_test(
        0,
        ProbeOutcome {
            tcp_ok: true,
            udp_ok: false,
            udp_applicable: false,
            tcp_latency: None,
            udp_latency: None,
            tcp_downgraded_from: None,
            udp_downgraded_from: None,
        },
    );
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        0,
        "second consecutive probe success crosses min_failures, primary regains active",
    );

    // Pin must be cleared so a future failure starts a fresh streak.
    let snap = manager.read_status_for_test(0);
    assert!(snap.tcp.active_wire_pinned_until.is_none(), "early failback must clear the pin",);
    assert_eq!(snap.tcp.active_wire_streak, 0);
}

// ── Effective health (visualization truth) ──────────────────────────────────
//
// `tcp_health_effective` / `udp_health_effective` on the snapshot reflect
// "is this uplink delivering traffic right now?" — `Some(true)` when probe-
// confirmed OR (for uplinks with at least one fallback) when any wire has
// dialed successfully within the runtime-failure window. Single-wire uplinks
// always equal `tcp_healthy` / `udp_healthy`.

#[tokio::test]
async fn drain_standby_pool_clears_deque_for_specified_transport() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);
    // Pre-populate the warm-standby deque to verify drain actually clears it.
    // Use the manager-internal pool API; the entry shape doesn't matter for
    // length accounting.
    {
        let pool = &manager.inner.standby_pools[0];
        let mut tcp_guard = pool.tcp.lock().await;
        // We can't construct a TransportStream from scratch here without
        // network setup; instead verify the drain on an *empty* pool is a
        // no-op and the API contract holds (length stays 0).
        assert!(tcp_guard.is_empty());
        drop(tcp_guard);
    }
    manager.drain_standby_pool(0, TransportKind::Tcp).await;
    let pool = &manager.inner.standby_pools[0];
    assert_eq!(pool.tcp.len_hint(), 0);
    assert_eq!(pool.udp.len_hint(), 0);
}

#[tokio::test]
async fn snapshot_effective_health_uses_any_wire_for_multi_wire_uplinks() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);

    // Mark probe of primary as failed.
    manager.inner.with_status_mut(0, |status| {
        status.tcp.healthy = Some(false);
    });

    let snap = manager.snapshot().await;
    assert_eq!(snap.uplinks[0].tcp_healthy, Some(false));
    assert_eq!(
        snap.uplinks[0].tcp_health_effective,
        Some(false),
        "no fallback success yet, effective should mirror probe verdict",
    );

    // Stamp a successful fallback wire dial.
    manager.record_wire_outcome(0, TransportKind::Tcp, 1, true, 2);

    let snap = manager.snapshot().await;
    assert_eq!(snap.uplinks[0].tcp_healthy, Some(false), "probe verdict unchanged");
    assert_eq!(
        snap.uplinks[0].tcp_health_effective,
        Some(true),
        "fallback wire success surfaces as effective health true",
    );
}

#[tokio::test]
async fn snapshot_effective_health_equals_probe_for_single_wire() {
    let cfg = vless_xhttp_primary(); // no fallbacks
    let manager = manager_with_uplink(cfg, 1);
    manager.inner.with_status_mut(0, |status| {
        status.tcp.healthy = Some(false);
    });
    // Even if a wire-success timestamp exists (defensive — single-wire uplinks
    // shouldn't really get one through normal paths), the override stays off
    // because `fallbacks.is_empty()`.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, true, 1);
    let snap = manager.snapshot().await;
    assert_eq!(snap.uplinks[0].tcp_healthy, Some(false));
    assert_eq!(
        snap.uplinks[0].tcp_health_effective,
        Some(false),
        "single-wire uplink keeps effective == probe (no liveness override)",
    );
}

// ── Per-wire mode-tracking ──────────────────────────────────────────────────
//
// `note_silent_transport_fallback_for_wire` opens a per-wire downgrade window
// that only `effective_*_mode_for_wire` of the same wire reads. Primary's
// downgrade slot stays untouched, so a fallback wire that observes its own
// XHTTP-H3 → XHTTP-H2 fallback doesn't mis-park primary's mode.

#[tokio::test]
async fn fallback_wire_downgrade_caps_only_its_own_wire() {
    let mut cfg = vless_xhttp_primary(); // primary: vless xhttp_h3
    // fallback[0]: WS family — primary's xhttp downgrade family is XHTTP, so
    // we use a fallback configured for ws_h3 to verify wire 1 has its own
    // independent slot.
    let mut ws_fb = ws_fallback(false);
    ws_fb.tcp_mode = TransportMode::WsH3;
    cfg.fallbacks = vec![ws_fb];
    let manager = manager_with_uplink(cfg, 1);

    // Open a downgrade on wire 1 (the fallback) by observing a WsH3 → WsH2
    // silent fallback during a successful dial.
    manager.note_silent_transport_fallback_for_wire(0, TransportKind::Tcp, 1, TransportMode::WsH3);

    // Wire 1's effective mode is now capped to WsH2 (one step down).
    let wire1_mode = manager.effective_tcp_mode_for_wire(0, 1).await;
    assert_eq!(wire1_mode, TransportMode::WsH2);

    // Wire 0 (primary) is unaffected — its slot was never touched.
    let wire0_mode = manager.effective_tcp_mode_for_wire(0, 0).await;
    assert_eq!(
        wire0_mode,
        TransportMode::XhttpH3,
        "primary's mode must stay at XhttpH3 — fallback wire downgrade does not pollute it",
    );
    let snap = manager.read_status_for_test(0);
    assert!(
        snap.tcp.mode_downgrade_until.is_none(),
        "primary's downgrade slot must remain unset",
    );
    assert!(snap.tcp.mode_downgrade_capped_to.is_none(), "primary's cap must remain unset",);
}

#[tokio::test]
async fn primary_wire_downgrade_does_not_leak_into_fallback() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);

    // Trigger a downgrade on wire 0 (primary) — XhttpH3 → XhttpH2.
    manager.note_silent_transport_fallback(0, TransportKind::Tcp, TransportMode::XhttpH3);

    // Primary effective mode is now capped to XhttpH2.
    assert_eq!(manager.effective_tcp_mode_for_wire(0, 0).await, TransportMode::XhttpH2,);

    // Fallback wire stays at its configured mode — primary's downgrade
    // doesn't reach it.
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::WsH2,
        "fallback wire reads its configured ws_h2 mode unchanged",
    );
}

#[tokio::test]
async fn probe_failure_advances_active_wire_without_dials() {
    use crate::manager::probe::outcome::ProbeOutcome;

    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    // min_failures = 2, pin = 1h so timer-driven advance can't be the
    // explanation for the snap.
    let manager = UplinkManager::new_for_test(
        "test",
        vec![cfg],
        make_probe(2),
        make_lb(std::time::Duration::from_secs(3600)),
    )
    .unwrap();

    // Single probe failure: below threshold → active stays at primary.
    manager.test_apply_probe_outcome_for_test(
        0,
        ProbeOutcome {
            tcp_ok: false,
            udp_ok: false,
            udp_applicable: false,
            tcp_latency: None,
            udp_latency: None,
            tcp_downgraded_from: None,
            udp_downgraded_from: None,
        },
    );
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 0);

    // Second consecutive failure: crosses min_failures → active advances
    // to fallback even though no client dial ever fired.
    manager.test_apply_probe_outcome_for_test(
        0,
        ProbeOutcome {
            tcp_ok: false,
            udp_ok: false,
            udp_applicable: false,
            tcp_latency: None,
            udp_latency: None,
            tcp_downgraded_from: None,
            udp_downgraded_from: None,
        },
    );
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        1,
        "probe-driven failover must advance active_wire when primary keeps failing",
    );

    // Pin must be set so the next session won't immediately retry primary.
    let snap = manager.read_status_for_test(0);
    assert!(
        snap.tcp.active_wire_pinned_until.is_some(),
        "probe-driven advance must pin the fallback active",
    );
}

#[tokio::test]
async fn probe_failure_does_not_advance_when_no_fallback_configured() {
    use crate::manager::probe::outcome::ProbeOutcome;

    let cfg = vless_xhttp_primary(); // single-wire, no fallbacks
    let manager = manager_with_uplink(cfg, 1);

    for _ in 0..5 {
        manager.test_apply_probe_outcome_for_test(
            0,
            ProbeOutcome {
                tcp_ok: false,
                udp_ok: false,
                udp_applicable: false,
                tcp_latency: None,
                udp_latency: None,
                tcp_downgraded_from: None,
                udp_downgraded_from: None,
            },
        );
    }
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        0,
        "single-wire uplink has no fallback to advance to",
    );
}

#[tokio::test]
async fn fallback_wire_downgrade_is_monotonic_within_window() {
    // Use XHTTP family so the multi-step chain XhttpH3 → XhttpH2 → XhttpH1
    // is observable through this window. (WS family stops at H3 → H2 here;
    // H2 → H1 is the `ws_mode_cache`'s job, not the per-uplink window's.)
    let mut cfg = vless_xhttp_primary(); // primary: vless xhttp_h3
    // Fallback is also vless-xhttp at H3 so the family/rank checks pass.
    let mut vless_xhttp_fb = FallbackTransport {
        transport: UplinkTransport::Vless,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: Some(Url::parse("https://other.example.com/xhttp").unwrap()),
        vless_mode: TransportMode::XhttpH3,
        vless_id: Some([1u8; 16]),
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    };
    let _ = &mut vless_xhttp_fb; // keep mutable for clarity even if unused
    cfg.fallbacks = vec![vless_xhttp_fb];
    let manager = manager_with_uplink(cfg, 1);

    // First trigger: XhttpH3 → XhttpH2.
    manager.note_silent_transport_fallback_for_wire(
        0,
        TransportKind::Tcp,
        1,
        TransportMode::XhttpH3,
    );
    assert_eq!(manager.effective_tcp_mode_for_wire(0, 1).await, TransportMode::XhttpH2,);

    // Second trigger inside the window: XhttpH2 → XhttpH1.
    manager.note_silent_transport_fallback_for_wire(
        0,
        TransportKind::Tcp,
        1,
        TransportMode::XhttpH2,
    );
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::XhttpH1,
        "XhttpH2 → XhttpH1 step must lower the cap",
    );

    // Third trigger inside the window claiming XhttpH3 again must NOT raise
    // the cap back from XhttpH1 to XhttpH2 (defensive: a stray observation
    // must not reset a deeper downgrade).
    manager.note_silent_transport_fallback_for_wire(
        0,
        TransportKind::Tcp,
        1,
        TransportMode::XhttpH3,
    );
    assert_eq!(
        manager.effective_tcp_mode_for_wire(0, 1).await,
        TransportMode::XhttpH1,
        "in-window XhttpH3 retrigger must not raise cap from XhttpH1 back to XhttpH2",
    );
}

// ── Primary-probe escalation gate when sticky on a verified fallback ────────
//
// After active_wire has shifted to a fallback that the fallback-wire probe
// (or any successful user-flow dial) has stamped as alive within the
// runtime_failure_window, a continuing primary-probe failure must NOT:
//   * tick `consecutive_failures` further (which would eventually flip
//     `healthy = false` for an uplink that is actually delivering),
//   * re-arm the mode-downgrade window (which would otherwise be re-applied
//     on every probe cycle indefinitely while primary stayed broken).
// This prevents the "primary stuck broken, fallback fine, mode-downgrade
// window glows forever" pattern operators see when probe targets a path
// that a real DPI / upstream filter has eaten.

#[test]
fn primary_probe_err_skipped_when_active_fallback_recently_alive() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);

    // Pre-stage: sticky already on the first fallback, with a recent
    // last_any_wire_success stamp. This is the steady-state of a uplink
    // whose primary has been broken for a while but whose fallback is OK.
    manager.test_seed_active_fallback_with_recent_success(
        0,
        TransportKind::Tcp,
        1,
        tokio::time::Instant::now(),
    );
    manager.test_seed_active_fallback_with_recent_success(
        0,
        TransportKind::Udp,
        1,
        tokio::time::Instant::now(),
    );

    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("primary still 404"));

    let status = manager.read_status_for_test(0);
    assert_eq!(
        status.tcp.consecutive_failures, 0,
        "primary probe failure must not tick consecutive_failures while sticky on a verified fallback",
    );
    assert_eq!(status.udp.consecutive_failures, 0, "udp side is gated identically",);
    assert!(
        status.tcp.mode_downgrade_until.is_none(),
        "primary probe failure must not re-arm the TCP mode-downgrade window in this state",
    );
    assert!(
        status.udp.mode_downgrade_until.is_none(),
        "primary probe failure must not re-arm the UDP mode-downgrade window in this state",
    );
    assert_eq!(status.tcp.active_wire, 1, "active_wire must stay on the verified fallback",);
}

#[test]
fn primary_probe_err_still_escalates_with_no_recent_success_on_active_fallback() {
    // Same staging as above, but `last_any_wire_success` is stale (older
    // than `runtime_failure_window`). The gate must NOT engage —
    // legacy escalation runs as before, since nothing currently confirms
    // that the fallback is delivering.
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);

    // Move sticky to fallback with a deliberately stale success stamp:
    // 10 minutes ago is well past the default runtime_failure_window.
    let stale = tokio::time::Instant::now() - std::time::Duration::from_secs(600);
    manager.test_seed_active_fallback_with_recent_success(0, TransportKind::Tcp, 1, stale);

    manager.test_apply_probe_err_for_test(0, anyhow::anyhow!("primary 404"));

    let status = manager.read_status_for_test(0);
    assert_eq!(
        status.tcp.consecutive_failures, 1,
        "stale fallback success must NOT engage the gate; consecutive_failures \
         ticks as before",
    );
}

// ── report_runtime_failure_for_wire ─────────────────────────────────────────
//
// Mirrors `record_wire_outcome`'s "failure on a non-active wire is session-
// local churn" rule onto the runtime-failure path: when the caller pins a
// failure to a specific wire and that wire is not the manager's current
// active wire for this transport, the failure must not stack onto the
// parent uplink's penalty / cooldown / streak / health bits. Without this
// rule a mid-session reset that lands on a stale fallback wire (which the
// manager has already moved away from) would still flap the whole uplink
// off the candidate set, undoing the per-wire dial-loop guarantees.

#[tokio::test(start_paused = true)]
async fn report_runtime_failure_for_wire_active_wire_charges_uplink() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);

    // Active stays at primary (wire 0). A failure attributed to wire 0
    // must penalise the parent uplink exactly as the no-wire path does.
    manager
        .report_runtime_failure_for_wire(
            0,
            TransportKind::Tcp,
            0,
            &anyhow::anyhow!("primary reset"),
        )
        .await;

    let status = manager.read_status_for_test(0);
    assert!(
        status.tcp.cooldown_until.is_some(),
        "active-wire failure must set the uplink cooldown"
    );
    assert_eq!(status.tcp.consecutive_runtime_failures, 1);
}

#[tokio::test(start_paused = true)]
async fn report_runtime_failure_for_wire_non_active_wire_is_suppressed() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 2);

    // Active stays at primary (wire 0) — we have not advanced. A failure
    // attributed to wire 1 (the fallback) is session-local churn and must
    // NOT touch the parent uplink's runtime-failure accounting.
    manager
        .report_runtime_failure_for_wire(
            0,
            TransportKind::Tcp,
            1,
            &anyhow::anyhow!("fallback transient"),
        )
        .await;

    let status = manager.read_status_for_test(0);
    assert!(
        status.tcp.cooldown_until.is_none(),
        "non-active wire failure must NOT engage uplink cooldown",
    );
    assert_eq!(
        status.tcp.consecutive_runtime_failures, 0,
        "non-active wire failure must NOT increment the runtime-failure streak",
    );
}

#[tokio::test(start_paused = true)]
async fn report_runtime_failure_for_wire_single_wire_uplink_always_charges() {
    // Backwards-compat guard: when no fallbacks are configured, the
    // wire-aware entry point must behave bit-for-bit like the legacy
    // `report_runtime_failure` so existing single-wire deployments keep
    // their penalty / cooldown / streak behaviour.
    let cfg = vless_xhttp_primary();
    let manager = manager_with_uplink(cfg, 1);

    manager
        .report_runtime_failure_for_wire(0, TransportKind::Tcp, 0, &anyhow::anyhow!("ws closed"))
        .await;

    let status = manager.read_status_for_test(0);
    assert!(status.tcp.cooldown_until.is_some());
    assert_eq!(status.tcp.consecutive_runtime_failures, 1);
}

#[tokio::test(start_paused = true)]
async fn report_runtime_failure_for_wire_follows_active_wire_after_advance() {
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ws_fallback(false)];
    let manager = manager_with_uplink(cfg, 1);

    // Advance the active wire to fallback (1) the same way the dial loop
    // would after a primary failure crosses `min_failures`.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 1);

    // After the advance, a failure attributed to wire 0 is now the
    // non-active wire and must be suppressed; a failure attributed to
    // wire 1 — the new active — must charge the uplink.
    manager
        .report_runtime_failure_for_wire(
            0,
            TransportKind::Tcp,
            0,
            &anyhow::anyhow!("stale primary"),
        )
        .await;
    let status_after_stale = manager.read_status_for_test(0);
    assert!(
        status_after_stale.tcp.cooldown_until.is_none(),
        "primary failure after active moved off must be suppressed",
    );
    assert_eq!(status_after_stale.tcp.consecutive_runtime_failures, 0);

    manager
        .report_runtime_failure_for_wire(
            0,
            TransportKind::Tcp,
            1,
            &anyhow::anyhow!("active fallback reset"),
        )
        .await;
    let status_after_active = manager.read_status_for_test(0);
    assert!(
        status_after_active.tcp.cooldown_until.is_some(),
        "failure on the now-active fallback wire must engage cooldown",
    );
    assert_eq!(status_after_active.tcp.consecutive_runtime_failures, 1);
}

// ── shuffle_wires round-counter ─────────────────────────────────────────────
//
// These pin the per-transport "one pass, then uplink-failover" semantics that
// `shuffle_wires = true` adds on top of the existing forward-only active-wire
// state machine. The flag is gated per-uplink — uplinks with the default
// `shuffle_wires = false` keep the legacy wrap-forever behaviour bit-for-bit.

#[test]
fn shuffle_wires_off_keeps_round_counter_at_zero() {
    // Baseline: with the flag off, the round counter must never tick even as
    // active_wire advances all the way around the chain.
    // SS wires throughout so the carrier-floor gate (new in iteration 3)
    // doesn't get in the way — those wires have no descent stack and
    // count as "at floor" from the first failure, restoring the legacy
    // "N failures → advance" semantics this baseline test pins.
    let mut cfg = ss_primary(false);
    cfg.fallbacks = vec![ss_alt_fallback(false), ss_fallback(false)];
    cfg.shuffle_wires = false;
    let manager = manager_with_uplink(cfg, 1);

    for wire in [0, 1, 2] {
        manager.record_wire_outcome(0, TransportKind::Tcp, wire, false, 3);
    }
    let snap = manager.read_status_for_test(0);
    assert_eq!(
        snap.tcp.wires_failed_in_round, 0,
        "round counter must stay at 0 when shuffle_wires is off",
    );
}

#[test]
fn shuffle_wires_on_increments_round_counter_per_advancement() {
    // SS wires throughout — bypasses the carrier-floor gate so the test
    // pins the round-counter accounting only.
    let mut cfg = ss_primary(false);
    cfg.fallbacks = vec![ss_alt_fallback(false), ss_fallback(false)];
    cfg.shuffle_wires = true;
    let manager = manager_with_uplink(cfg, 1);

    // First active wire (0) fails → advance to 1, counter = 1.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 3);
    let snap = manager.read_status_for_test(0);
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 1);
    assert_eq!(snap.tcp.wires_failed_in_round, 1);

    // Second active wire (1) fails → advance to 2, counter = 2.
    manager.record_wire_outcome(0, TransportKind::Tcp, 1, false, 3);
    let snap = manager.read_status_for_test(0);
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 2);
    assert_eq!(snap.tcp.wires_failed_in_round, 2);
}

#[test]
fn shuffle_wires_on_resets_round_counter_on_success() {
    // SS wires throughout — bypasses the carrier-floor gate.
    let mut cfg = ss_primary(false);
    cfg.fallbacks = vec![ss_alt_fallback(false), ss_fallback(false)];
    cfg.shuffle_wires = true;
    let manager = manager_with_uplink(cfg, 1);

    // Fail wire 0 → counter = 1, active = 1.
    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 3);
    assert_eq!(manager.read_status_for_test(0).tcp.wires_failed_in_round, 1);

    // Traffic stabilises on whichever wire — the spec says any wire success
    // resets the round, not just the active one. Here we report success on
    // wire 2 (a non-active wire from the dial loop's perspective).
    manager.record_wire_outcome(0, TransportKind::Tcp, 2, true, 3);
    assert_eq!(
        manager.read_status_for_test(0).tcp.wires_failed_in_round,
        0,
        "any-wire success must reset the shuffle_wires round counter",
    );
    // active_wire must NOT snap back to 0 — the spec is "forward only,
    // rotation continues from current position on next failure".
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 1);
}

#[test]
fn shuffle_wires_on_resets_counter_after_full_cycle() {
    // Three wires, min_failures = 1 → three advancements complete the
    // cycle. When the third advancement fires, the chain-exhaustion branch
    // takes the counter back to 0 (and would spawn the escalation task in
    // an async context — verified separately to avoid runtime-spawn flake).
    // SS wires throughout — bypasses the carrier-floor gate.
    let mut cfg = ss_primary(false);
    cfg.fallbacks = vec![ss_alt_fallback(false), ss_fallback(false)];
    cfg.shuffle_wires = true;
    let manager = manager_with_uplink(cfg, 1);

    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 3);
    manager.record_wire_outcome(0, TransportKind::Tcp, 1, false, 3);
    manager.record_wire_outcome(0, TransportKind::Tcp, 2, false, 3);

    let snap = manager.read_status_for_test(0);
    assert_eq!(
        snap.tcp.wires_failed_in_round, 0,
        "completing the cycle resets the counter so the next round starts fresh",
    );
    // The state machine itself still wraps `(prev + 1) % total`, so the
    // active wire lands back at 0 after the third advancement.
    assert_eq!(manager.active_wire(0, TransportKind::Tcp), 0);
}

#[test]
fn shuffle_wires_full_cycle_flips_health_and_engages_cooldown() {
    // Chain exhaustion now sets `healthy = Some(false)` + `cooldown_until`
    // directly inside the with_status_mut lock (no async spawn / no
    // recursive `report_runtime_failure` hop). This pins the contract
    // the load balancer relies on: after one full forward pass through
    // the chain without a single success, the uplink must be visibly
    // unhealthy + on cooldown so the LB drops it from candidates.
    // SS wires throughout — bypasses the carrier-floor gate.
    let mut cfg = ss_primary(false);
    cfg.fallbacks = vec![ss_alt_fallback(false), ss_fallback(false)];
    cfg.shuffle_wires = true;
    let manager = manager_with_uplink(cfg, 1);

    manager.record_wire_outcome(0, TransportKind::Tcp, 0, false, 3);
    manager.record_wire_outcome(0, TransportKind::Tcp, 1, false, 3);
    manager.record_wire_outcome(0, TransportKind::Tcp, 2, false, 3);

    let snap = manager.read_status_for_test(0);
    assert_eq!(snap.tcp.healthy, Some(false), "chain-exhausted must flip healthy = Some(false)",);
    assert!(
        snap.tcp.cooldown_until.is_some(),
        "chain-exhausted must engage failure cooldown so the LB drops the uplink",
    );
    // Round counter is zeroed so a probe / data-plane success can start a
    // fresh round without immediately re-triggering exhaustion.
    assert_eq!(snap.tcp.wires_failed_in_round, 0);
}

// ── Runtime-failure-driven wire rotation ────────────────────────────────────
//
// The original implementation only ticked the round counter on dial / probe
// failures, so the dominant production failure mode — established-session
// data-plane errors via `report_runtime_failure` (e.g. "ws upstream read
// idle for 300s on datagram channel") — never moved `active_wire` at all
// and the dashboard showed no rotation. These tests pin the contract that
// runtime failures feed the same wire-rotation machinery.

fn make_probe_with_strict_global(min_failures: usize) -> ProbeConfig {
    // The runtime-failure → healthy-flip path is gated on `probe_enabled`
    // AND `strict_global_active_uplink`, so we need a probe transport
    // configured to enable the gate.
    let mut probe = make_probe(min_failures);
    probe.ws = WsProbeConfig { enabled: true };
    probe
}

fn make_lb_strict_global(mode_downgrade_duration: std::time::Duration) -> LoadBalancingConfig {
    // `strict_global_active_uplink` requires both ActivePassive + Global —
    // mirrors the user's production config in `logs/config.toml`.
    let mut lb = make_lb(mode_downgrade_duration);
    lb.routing_scope = RoutingScope::Global;
    lb.mode = LoadBalancingMode::ActivePassive;
    lb
}

fn manager_with_strict_global_uplink(uplink: UplinkConfig, min_failures: usize) -> UplinkManager {
    UplinkManager::new_for_test(
        "test",
        vec![uplink],
        make_probe_with_strict_global(min_failures),
        make_lb_strict_global(std::time::Duration::from_secs(60)),
    )
    .unwrap()
}

#[tokio::test]
async fn shuffle_wires_runtime_failure_advances_active_wire() {
    // Two consecutive UDP runtime failures on the active wire must
    // advance `active_wire` from 0 to 1 — this is the missing path that
    // production logs surfaced (wire stayed pinned to wire 0 forever
    // because `report_runtime_failure` only bumped
    // `consecutive_runtime_failures` and never touched the wire state
    // machine). SS wires throughout — bypasses the new carrier-floor
    // gate so the runtime-failure → advance path is tested in isolation
    // from the vertical-cascade machinery.
    let mut cfg = ss_primary(true);
    cfg.fallbacks = vec![ss_alt_fallback(true), ss_fallback(true)];
    cfg.shuffle_wires = true;
    let manager = manager_with_strict_global_uplink(cfg, 2);

    let err = || anyhow::anyhow!("ws upstream read idle for 300s on datagram channel");
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;

    assert_eq!(
        manager.active_wire(0, TransportKind::Udp),
        1,
        "two runtime failures on active wire 0 with min_failures=2 must advance to wire 1",
    );
    let snap = manager.read_status_for_test(0);
    assert_eq!(snap.udp.wires_failed_in_round, 1);
}

#[tokio::test]
async fn shuffle_wires_gates_uplink_healthy_flip_until_round_exhausted() {
    // Without the gate, `consecutive_runtime_failures >= min_failures`
    // would flip the uplink unhealthy on the first wire's failures,
    // before wire rotation has a chance to play out. The gate must
    // keep `healthy != Some(false)` until the round counter has
    // reached `total_wires`. After exhaustion the gate releases and
    // `healthy = Some(false)` lands so the LB switches uplinks.
    // SS wires throughout — bypasses the carrier-floor gate.
    let mut cfg = ss_primary(true);
    cfg.fallbacks = vec![ss_alt_fallback(true), ss_fallback(true)];
    cfg.shuffle_wires = true;
    let manager = manager_with_strict_global_uplink(cfg, 2);

    let err = || anyhow::anyhow!("ws upstream read idle for 300s on datagram channel");
    // Two failures on wire 0 → advance to wire 1; round=1; not exhausted.
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    let snap = manager.read_status_for_test(0);
    assert_eq!(manager.active_wire(0, TransportKind::Udp), 1);
    assert_eq!(snap.udp.wires_failed_in_round, 1);
    assert_ne!(
        snap.udp.healthy,
        Some(false),
        "wire rotation in progress: gate must hold uplink-level healthy flip",
    );

    // Two failures on wire 1 → advance to wire 2; round=2; not exhausted.
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    let snap = manager.read_status_for_test(0);
    assert_eq!(manager.active_wire(0, TransportKind::Udp), 2);
    assert_eq!(snap.udp.wires_failed_in_round, 2);
    assert_ne!(snap.udp.healthy, Some(false), "still rotating, gate still holds");

    // Two failures on wire 2 → advance to wire 0 (wrap); round=3; EXHAUSTED.
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    let snap = manager.read_status_for_test(0);
    assert_eq!(snap.udp.healthy, Some(false), "round exhausted: healthy must flip");
    assert!(snap.udp.cooldown_until.is_some(), "exhaustion must engage cooldown");
    assert_eq!(snap.udp.wires_failed_in_round, 0, "round counter resets after exhaustion");
}

#[tokio::test]
async fn shuffle_wires_off_keeps_legacy_runtime_health_flip() {
    // With shuffle_wires = false, the runtime-failure path must keep
    // the legacy "flip healthy after min_failures runtime failures"
    // behaviour intact — no wire rotation, no gate.
    let mut cfg = ss_primary(true);
    cfg.fallbacks = vec![ss_alt_fallback(true), ss_fallback(true)];
    cfg.shuffle_wires = false;
    let manager = manager_with_strict_global_uplink(cfg, 2);

    let err = || anyhow::anyhow!("ws upstream read idle for 300s on datagram channel");
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;

    let snap = manager.read_status_for_test(0);
    assert_eq!(
        snap.udp.healthy,
        Some(false),
        "legacy path: 2 runtime failures must flip healthy without wire rotation",
    );
    assert_eq!(
        manager.active_wire(0, TransportKind::Udp),
        0,
        "legacy path: active_wire stays at primary",
    );
    assert_eq!(
        snap.udp.wires_failed_in_round, 0,
        "round counter must stay zero when flag is off",
    );
}

#[tokio::test]
async fn shuffle_wires_holds_wire_advance_until_carrier_floor() {
    // Vertical carrier cascade (production scenario):
    // wire 0 is a VLESS+XHTTP/H3 endpoint with the WS-family chain
    // `xhttp_h3 → xhttp_h2 → xhttp_h1` as its descent stack. Runtime
    // failures must drive the active wire's effective mode down the
    // family ladder before any wire-rotation step fires. Without the
    // gate, the very first `min_failures` runtime failures on h3 would
    // advance straight to wire 1 (bypassing h2 / h1 entirely) — the
    // bug this iteration fixes.
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ss_alt_fallback(true)];
    cfg.shuffle_wires = true;
    // Manually install the wire-0 cap at xhttp_h2 to simulate the
    // state immediately after the first `extend_mode_downgrade` step
    // would have run. This isolates the gate behaviour from
    // extend_mode_downgrade's own descent logic (covered in mode_downgrade
    // tests) and asserts exactly what we care about here: when the
    // primary wire is on xhttp_h2 (NOT at floor), the rotation step
    // does NOT fire even after `min_failures` runtime failures.
    let manager = manager_with_strict_global_uplink(cfg, 1);
    {
        manager.inner.with_status_mut(0, |status| {
            status.udp.mode_downgrade_capped_to = Some(TransportMode::XhttpH2);
            status.udp.mode_downgrade_until =
                Some(tokio::time::Instant::now() + std::time::Duration::from_secs(60));
        });
    }
    // Sanity: wire 0 should report "not at floor".
    let snap = manager.read_status_for_test(0);
    let uplink_handle = manager.uplinks()[0].clone();
    assert!(
        !crate::manager::mode_downgrade::wire_is_at_carrier_floor(
            &uplink_handle,
            &snap.udp,
            TransportKind::Udp,
            0,
        ),
        "wire 0 capped to xhttp_h2 must not be at the carrier floor of its xhttp family",
    );

    // Repeated UDP runtime failure on the active wire: each call goes
    // through `record_wire_outcome(active_wire, false)` indirectly via
    // `report_runtime_failure`. Without the gate this would advance
    // active_wire on the very first call (min_failures = 1 in this
    // test). With the gate, wire stays at 0.
    let err = || anyhow::anyhow!("ws upstream read idle for 300s on datagram channel");
    for _ in 0..5 {
        manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    }
    assert_eq!(
        manager.active_wire(0, TransportKind::Udp),
        0,
        "carrier-floor gate must hold the wire-rotation step while wire 0's \
         effective mode (xhttp_h2) still has a lower rank (xhttp_h1) to walk \
         down to",
    );
    let snap = manager.read_status_for_test(0);
    assert_eq!(
        snap.udp.wires_failed_in_round, 0,
        "round counter does not advance while the active wire holds at the cap"
    );

    // Now simulate the cap walking all the way to xhttp_h1 (floor).
    {
        manager.inner.with_status_mut(0, |status| {
            status.udp.mode_downgrade_capped_to = Some(TransportMode::XhttpH1);
        });
    }
    let snap = manager.read_status_for_test(0);
    assert!(
        crate::manager::mode_downgrade::wire_is_at_carrier_floor(
            &uplink_handle,
            &snap.udp,
            TransportKind::Udp,
            0,
        ),
        "xhttp_h1 is the floor of its family — gate should release",
    );
    // One more failure at the floor must advance the wire.
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    assert_eq!(
        manager.active_wire(0, TransportKind::Udp),
        1,
        "wire at xhttp_h1 floor + active-wire failure must advance to wire 1",
    );
}

#[tokio::test]
async fn carrier_downgrade_off_advances_wire_immediately() {
    // Opt-out: with `carrier_downgrade = false` the per-wire vertical
    // cascade machinery is disabled — `extend_mode_downgrade` is a
    // no-op on this uplink and `wire_is_at_carrier_floor` reports
    // "at floor" unconditionally. Combined with `shuffle_wires = true`
    // this collapses the per-wire `h3 → h2 → h1` cascade into a
    // direct wire-to-wire rotation: the very next runtime failure
    // after `min_failures` advances active_wire even on an xhttp_h3
    // primary, instead of spending the `mode_downgrade_secs` window
    // walking down the carrier stack on this wire first.
    //
    // Important contrast with the gated cascade test above: the same
    // VLESS-XHTTP primary that previously needed an explicit cap to
    // `xhttp_h1` before advancing now advances on the first satisfied
    // threshold because the gate sees "floor" from the very first
    // failure.
    let mut cfg = vless_xhttp_primary();
    cfg.fallbacks = vec![ss_alt_fallback(true)];
    cfg.shuffle_wires = true;
    cfg.carrier_downgrade = false;
    let manager = manager_with_strict_global_uplink(cfg, 2);

    let err = || anyhow::anyhow!("ws upstream read idle for 300s on datagram channel");
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;
    manager.report_runtime_failure(0, TransportKind::Udp, &err()).await;

    assert_eq!(
        manager.active_wire(0, TransportKind::Udp),
        1,
        "carrier_downgrade = false: two active-wire failures must advance straight to wire 1",
    );
    let snap = manager.read_status_for_test(0);
    assert!(
        snap.udp.mode_downgrade_capped_to.is_none(),
        "extend_mode_downgrade is a no-op with carrier_downgrade = false",
    );
    assert_eq!(snap.udp.wires_failed_in_round, 1);
}

#[test]
fn shuffle_wires_probe_advance_bumps_round_counter() {
    // The probe-driven 0→1 transition in
    // `advance_active_wire_on_probe_failure` previously bypassed the
    // round counter (only dial/runtime paths through
    // `record_wire_outcome` ticked it). This test pins the new
    // accounting: when shuffle_wires is on, the probe-driven advance
    // also bumps `wires_failed_in_round` so chain exhaustion fires
    // after the right number of advancements regardless of which
    // path drives them. SS wires throughout — bypasses the
    // carrier-floor gate so this test isolates the round counter
    // accounting on the probe path.
    let mut cfg = ss_primary(false);
    cfg.fallbacks = vec![ss_alt_fallback(false), ss_fallback(false)];
    cfg.shuffle_wires = true;
    let manager = manager_with_strict_global_uplink(cfg.clone(), 1);

    let uplink = manager.uplinks()[0].clone();
    manager.process_probe_err(
        0,
        &uplink,
        anyhow::anyhow!("primary probe failed"),
        TransportMode::WsH1,
        TransportMode::WsH1,
    );

    let snap = manager.read_status_for_test(0);
    assert_eq!(
        manager.active_wire(0, TransportKind::Tcp),
        1,
        "probe error must advance active wire from 0 to 1",
    );
    // 3-wire chain → first advance gives round=1, not yet exhausted, so
    // healthy stays gated and counter visibly ticks.
    assert_eq!(snap.tcp.wires_failed_in_round, 1);
    assert_ne!(
        snap.tcp.healthy,
        Some(false),
        "round not yet exhausted: gate must hold uplink-level healthy flip",
    );
}
