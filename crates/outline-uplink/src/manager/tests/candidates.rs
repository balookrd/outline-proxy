//! Global active-passive failover regression.
//!
//! Reproduces the field failure where, in `routing_scope = "global"` +
//! `active_passive`, an active uplink whose server has died keeps the global
//! active slot forever and traffic never moves to a healthy standby.
//!
//! The dead server fails in the "front alive, back dead" mode: every wire of
//! the uplink dials the same host, whose edge still completes the WebSocket
//! handshake intermittently but immediately closes the data path
//! (`Close 1013 Try Again Later`). That intermittent transport-level success,
//! combined with `shuffle_wires` round-gating and active-wire stickiness,
//! suppresses the `healthy = Some(false)` flip that global failover relies on
//! (see `strict_transport_candidates`: in global + probe mode `should_keep`
//! ignores cooldown and only reacts to a probe-confirmed health flip).

use std::time::Duration;

use anyhow::anyhow;
use socks5_proto::TargetAddr;
use url::Url;

use crate::config::{
    CipherKind, FallbackTransport, LoadBalancingConfig, LoadBalancingMode, ProbeConfig,
    RoutingScope, TransportMode, UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::manager::probe::outcome::ProbeOutcome;
use crate::types::{TransportKind, UplinkManager};

fn ss_fallback(tag: &str) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse(&format!("wss://dead.example.com/{tag}/tcp")).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(&format!("wss://dead.example.com/{tag}/udp")).unwrap()),
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

/// Multi-wire SS uplink (primary + two fallbacks), `shuffle_wires` on — the
/// exact shape of the field uplink whose three wires all point at one host.
fn dead_uplink(name: &str, weight: f64) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://dead.example.com/primary/tcp").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse("wss://dead.example.com/primary/udp").unwrap()),
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
        weight,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: vec![ss_fallback("fb1"), ss_fallback("fb2")],
        shuffle_wires: true,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

/// Plain single-wire healthy standby.
fn healthy_uplink(name: &str, weight: f64) -> UplinkConfig {
    let mut u = dead_uplink(name, weight);
    u.tcp_ws_url = Some(Url::parse("wss://live.example.com/primary/tcp").unwrap());
    u.udp_ws_url = Some(Url::parse("wss://live.example.com/primary/udp").unwrap());
    u.fallbacks = Vec::new();
    u.shuffle_wires = false;
    u
}

fn lb_global() -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActivePassive,
        routing_scope: RoutingScope::Global,
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

fn probe_enabled() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(10),
        timeout: Duration::from_secs(10),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 2,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
        ws: WsProbeConfig { enabled: true },
        http: None,
        dns: None,
        tcp: None,
        tls: None,
    }
}

fn probe_ok() -> ProbeOutcome {
    ProbeOutcome {
        tcp_ok: true,
        udp_ok: true,
        udp_applicable: true,
        tcp_latency: Some(Duration::from_millis(30)),
        udp_latency: Some(Duration::from_millis(30)),
        tcp_downgraded_from: None,
        udp_downgraded_from: None,
    }
}

fn ws_close_1013() -> anyhow::Error {
    anyhow!("websocket read failed: IO error: Invalid close code: 1013: Invalid close code: 1013")
}

fn manager() -> UplinkManager {
    UplinkManager::new_for_test(
        "main",
        vec![dead_uplink("up-a", 2.0), healthy_uplink("up-b", 1.0)],
        probe_enabled(),
        lb_global(),
    )
    .unwrap()
}

/// In `routing_scope = "global"` + `active_passive`, when the active uplink's
/// server dies (handshake intermittently succeeds, data path dead) the global
/// active slot MUST move to the healthy standby.
#[tokio::test]
async fn global_active_fails_over_when_active_uplink_server_dies() {
    let manager = manager();

    // Both healthy at first; up-a (higher weight) wins the initial selection.
    manager.test_apply_probe_outcome_for_test(0, probe_ok());
    manager.test_apply_probe_outcome_for_test(1, probe_ok());
    let _ = manager
        .strict_transport_candidates(TransportKind::Tcp, None, None, true)
        .await;
    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(0),
        "up-a should win the initial global selection on weight",
    );

    // up-a's server degrades: every wire dials the same host, whose edge keeps
    // completing the WS handshake but the data path is dead (Close 1013). Each
    // cycle models the real signals the manager sees:
    //   * the primary probe fails (data path through primary is dead);
    //   * a real flow's dial handshake succeeds, so the dispatcher confirms the
    //     selection (`confirm_selected_uplink` resets the runtime streak on a
    //     dial that is NOT end-to-end), then the read returns Close 1013;
    //   * every few cycles the edge also completes a bare *wire* dial handshake
    //     (`record_wire_outcome(success=true)` — see udp/transport.rs and
    //     tcp/failover.rs). Before the fix this stamped `last_any_wire_success`
    //     and reset the `shuffle_wires` round counter, masking the data-plane
    //     death so the health flip never fired — the heart of the bug. The fix
    //     makes a bare dial advance only the wire-rotation streak, so the round
    //     counter still reaches exhaustion and the uplink flips unhealthy.
    let target = TargetAddr::Domain("example.com".to_string(), 443);
    for i in 0..40 {
        manager.test_apply_probe_err_for_test(0, anyhow!("tcp probe timed out after 10s"));
        let _ = manager.tcp_candidates(&target).await;
        manager
            .confirm_selected_uplink(TransportKind::Tcp, Some(&target), 0)
            .await;
        manager
            .report_runtime_failure(0, TransportKind::Tcp, &ws_close_1013())
            .await;
        if i % 3 == 2 {
            let active = manager.active_wire(0, TransportKind::Tcp);
            manager.record_wire_outcome(0, TransportKind::Tcp, active, true, 3);
        }
        // up-b stays fully healthy the whole time.
        manager.test_apply_probe_outcome_for_test(1, probe_ok());
    }

    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(1),
        "global active must fail over from dead up-a to healthy up-b; \
         tcp_healthy(0)={:?}, active_wire(0)={}",
        manager.test_tcp_healthy(0).await,
        manager.active_wire(0, TransportKind::Tcp),
    );
}

/// Variant where the **probe keeps succeeding** while the data path is dead.
///
/// This is the field case behind "a server reboot does not fail the client
/// over": the active uplink's edge answers the lightweight probe handshake on
/// every cycle (front alive) while every real flow dials fine and is then
/// closed with `Close 1013` (back dead). Each probe success used to call
/// `record_transport_success`, which reset `consecutive_runtime_failures`, the
/// shuffle round counter (`wires_failed_in_round`) and the runtime cooldown and
/// re-armed `healthy = Some(true)`. Since the probe runs far more often than the
/// sparse data-plane failures, it erased the death signal every interval, the
/// shuffle round never exhausted, `healthy` never flipped to `Some(false)`, and
/// the global active slot stuck to the dead uplink forever.
///
/// With the fix a probe success no longer overwrites a freshly-recorded
/// data-plane death (it is a handshake, not delivery), so the runtime failures
/// drive the shuffle round to exhaustion, `healthy` flips, and global failover
/// moves to the healthy standby.
#[tokio::test]
async fn global_active_fails_over_when_probe_passes_but_data_path_is_dead() {
    let manager = manager();

    // Both healthy at first; up-a (higher weight) wins the initial selection.
    manager.test_apply_probe_outcome_for_test(0, probe_ok());
    manager.test_apply_probe_outcome_for_test(1, probe_ok());
    let _ = manager
        .strict_transport_candidates(TransportKind::Tcp, None, None, true)
        .await;
    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(0),
        "up-a should win the initial global selection on weight",
    );

    // up-a's edge stays handshake-alive but data-dead: a real flow dials fine
    // (selection confirmed), then the read fails with Close 1013, and the probe
    // still reports the edge as alive on every cycle.
    let target = TargetAddr::Domain("example.com".to_string(), 443);
    for _ in 0..40 {
        let _ = manager.tcp_candidates(&target).await;
        manager
            .confirm_selected_uplink(TransportKind::Tcp, Some(&target), 0)
            .await;
        manager
            .report_runtime_failure(0, TransportKind::Tcp, &ws_close_1013())
            .await;
        // The probe keeps succeeding on the dead uplink the entire time.
        manager.test_apply_probe_outcome_for_test(0, probe_ok());
        // up-b stays fully healthy.
        manager.test_apply_probe_outcome_for_test(1, probe_ok());
    }

    // A fresh dispatch now that up-a is data-plane-confirmed dead.
    let _ = manager.tcp_candidates(&target).await;
    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(1),
        "global active must fail over to healthy up-b even though up-a's probe \
         keeps passing; tcp_healthy(0)={:?}, active_wire(0)={}",
        manager.test_tcp_healthy(0).await,
        manager.active_wire(0, TransportKind::Tcp),
    );
}

/// Operator on/off: administratively disabling the active uplink must take it
/// out of selection immediately (failing over to the enabled standby) and keep
/// it out of the candidate set until it is re-enabled.
#[tokio::test]
async fn disabling_active_uplink_fails_over_and_excludes_it_from_selection() {
    let manager = manager();
    let target = TargetAddr::Domain("example.com".to_string(), 443);

    // Both healthy; up-a (higher weight) wins the initial global selection.
    manager.test_apply_probe_outcome_for_test(0, probe_ok());
    manager.test_apply_probe_outcome_for_test(1, probe_ok());
    let _ = manager
        .strict_transport_candidates(TransportKind::Tcp, None, None, true)
        .await;
    assert_eq!(manager.global_active_uplink_index().await, Some(0));

    // Disable the active uplink → it must drop out and traffic move to up-b.
    let idx = manager.set_uplink_enabled_by_name("up-a", false).await.unwrap();
    assert_eq!(idx, 0);
    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(1),
        "disabling the active uplink must fail over to the enabled standby",
    );

    // up-a must not appear in any candidate set while disabled.
    let cands = manager.tcp_candidates(&target).await;
    assert!(
        cands.iter().all(|c| c.index != 0),
        "a disabled uplink must be excluded from candidates",
    );
    assert!(
        manager.test_admin_disabled(0),
        "snapshot must report the uplink as admin-disabled",
    );

    // Re-enable up-a, then disable up-b (the current active). Failover must
    // land on the re-enabled up-a — proving it is selectable again. (In strict
    // global with auto_failback off, a healthy active is sticky, so we force the
    // move by disabling up-b rather than expecting an automatic failback.)
    manager.set_uplink_enabled_by_name("up-a", true).await.unwrap();
    manager.test_apply_probe_outcome_for_test(0, probe_ok());
    assert!(!manager.test_admin_disabled(0));
    manager.set_uplink_enabled_by_name("up-b", false).await.unwrap();
    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(0),
        "after re-enabling up-a and disabling up-b, the active slot must move to up-a",
    );
}

/// A 1013 "try again later" is a per-target upstream failure (the server could
/// not reach THIS destination), not an uplink/tunnel fault. It must NOT stamp an
/// uplink cooldown — otherwise a routine per-destination 1013 drives
/// `health_effective` DOWN for the cooldown window and flaps the uplink
/// indicator even though the tunnel is fine. It MUST still feed the
/// consecutive-runtime-failure counter, so a genuinely dead backend (1013 on
/// everything) still escalates to a health flip and failover.
#[tokio::test]
async fn try_again_1013_skips_cooldown_but_still_counts() {
    let manager = manager();

    // 1013 try-again on up-a: no cooldown, but the streak advances.
    manager
        .report_runtime_failure(0, TransportKind::Tcp, &ws_close_1013())
        .await;
    let st = manager.read_status_for_test(0);
    assert!(
        st.tcp.cooldown_until.is_none(),
        "a 1013 try-again must NOT set an uplink cooldown (would flap health_effective)",
    );
    assert_eq!(
        st.tcp.consecutive_runtime_failures, 1,
        "a 1013 try-again must still count toward the escalation threshold",
    );

    // A genuine transport error DOES take the cooldown path (unchanged).
    manager
        .report_runtime_failure(1, TransportKind::Tcp, &anyhow!("connection reset by peer"))
        .await;
    let st1 = manager.read_status_for_test(1);
    assert!(
        st1.tcp.cooldown_until.is_some(),
        "a real transport error must still set the runtime cooldown",
    );
}
