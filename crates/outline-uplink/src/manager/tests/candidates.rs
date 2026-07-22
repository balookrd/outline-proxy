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
        tun_icmp_liveness_window: None,
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
        endpoint_check: false,
        endpoint_check_timeout: Duration::from_millis(2000),
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
        tcp_carrier_ok: true,
        udp_ok: true,
        udp_carrier_ok: true,
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

/// Probe-driven failover WITHOUT client traffic: when the probe cycle marks the
/// strict active uplink unhealthy, the active slot must move to a healthy
/// standby at the END of that cycle — not only when a client dial happens to
/// re-run selection. Models an idle TUN client right after a restart that
/// restored a now-dead active uplink from the state store: nothing dials, so the
/// per-probe-cycle re-selection (`reselect_strict_active_after_probe`) is the
/// only failover driver. Regression for "the dead active uplink never fails
/// over" on an idle client.
#[tokio::test]
async fn strict_active_fails_over_on_probe_cycle_without_client_traffic() {
    let manager = manager();

    // Both healthy; up-a (higher weight) wins the initial global selection.
    manager.test_apply_probe_outcome_for_test(0, probe_ok());
    manager.test_apply_probe_outcome_for_test(1, probe_ok());
    let _ = manager
        .strict_transport_candidates(TransportKind::Tcp, None, None, true)
        .await;
    assert_eq!(manager.global_active_uplink_index().await, Some(0));

    // The probe cycle confirms up-a dead on both legs (unhealthy + cooldown, the
    // state a runtime/probe failure leaves behind) while up-b stays healthy.
    // Crucially, NO `tcp_candidates` / client dial happens here.
    manager.test_set_tcp_health(0, false, 0).await;
    manager.test_set_udp_health(0, false, 0).await;
    manager.inner.with_status_mut(0, |s| {
        let until = tokio::time::Instant::now() + Duration::from_secs(10);
        s.tcp.cooldown_until = Some(until);
        s.udp.cooldown_until = Some(until);
    });
    manager.test_set_tcp_health(1, true, 30).await;
    manager.test_set_udp_health(1, true, 30).await;

    // The end-of-probe-cycle re-selection (the fix) must promote the healthy
    // standby with no client traffic. Before the fix, selection only re-ran on a
    // dial, so an idle client kept the dead active pinned indefinitely.
    manager.reselect_strict_active_after_probe().await;
    assert_eq!(
        manager.global_active_uplink_index().await,
        Some(1),
        "probe-driven failover must promote healthy up-b without any client dial; \
         tcp_healthy(0)={:?}",
        manager.test_tcp_healthy(0).await,
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

/// A server-initiated downstream-throttle signal is the OPPOSITE of a 1013: the
/// tunnel itself is the problem (the carrier toward this client is throttled),
/// so it MUST stamp an uplink cooldown and advance the streak — that is what
/// drives health-weighted selection to migrate traffic to another uplink.
#[tokio::test]
async fn downstream_throttle_sets_cooldown_and_counts() {
    let manager = manager();

    manager.report_downstream_throttle(0, TransportKind::Tcp).await;
    let st = manager.read_status_for_test(0);
    assert!(
        st.tcp.cooldown_until.is_some(),
        "a downstream-throttle signal MUST set an uplink cooldown so selection migrates away",
    );
    assert_eq!(
        st.tcp.consecutive_runtime_failures, 1,
        "a downstream-throttle signal must advance the runtime-failure streak",
    );
    // The dashboard counter ticks on the signalled transport only.
    assert_eq!(
        st.tcp.downstream_throttle_count, 1,
        "the throttle counter must tick for the dashboard chip",
    );
    assert!(
        st.tcp.last_downstream_throttle_at.is_some(),
        "the last-throttle timestamp is set"
    );
    assert_eq!(
        st.udp.downstream_throttle_count, 0,
        "the other transport's counter is untouched"
    );
}

fn lb_per_flow() -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
        ..lb_global()
    }
}

/// up-a is multi-wire (its status can move `active_wire` onto a fallback), up-b
/// is single-wire; equal weight, so the order is decided by score alone.
fn per_flow_manager() -> UplinkManager {
    UplinkManager::new_for_test(
        "main",
        vec![dead_uplink("up-a", 1.0), healthy_uplink("up-b", 1.0)],
        probe_enabled(),
        lb_per_flow(),
    )
    .unwrap()
}

/// Candidate ordering ranks uplinks by the RTT of the wire that is **actually
/// carrying traffic**: once `active_wire` has moved to a fallback, that
/// fallback's EWMA — not primary's — is the uplink's score.
///
/// Guards the candidate-building fast path: it now copies a scoring projection
/// out from under the status lock instead of cloning the whole `UplinkStatus`,
/// and the per-wire EWMA slots (a `Vec` on the status) are exactly the input a
/// projection is most likely to drop. Dropping it would score up-a by primary's
/// stale 10 ms and hand it every flow, even though its live wire measures 200 ms.
#[tokio::test]
async fn candidate_order_ranks_by_active_wire_rtt() {
    let target = TargetAddr::Domain("example.com".to_string(), 443);

    let manager = per_flow_manager();
    manager.test_set_tcp_health(0, true, 10).await;
    manager.test_set_tcp_health(1, true, 50).await;
    // up-a has descended onto its first fallback wire, which measures 200 ms.
    manager.inner.with_status_mut(0, |s| {
        s.tcp.active_wire = 1;
        s.tcp.fallback_rtt_ewma = vec![Some(Duration::from_millis(200))];
    });

    let order: Vec<usize> = manager
        .tcp_candidates(&target)
        .await
        .iter()
        .map(|c| c.index)
        .collect();
    assert_eq!(
        order.first().copied(),
        Some(1),
        "up-a rides a 200 ms fallback wire, so the 50 ms up-b must be preferred; got {order:?}",
    );

    // Same statuses, except up-a is back on its primary wire (10 ms) — it must
    // win the flow again. A fresh manager keeps the earlier sticky route from
    // masking the re-ranking.
    let manager = per_flow_manager();
    manager.test_set_tcp_health(0, true, 10).await;
    manager.test_set_tcp_health(1, true, 50).await;
    manager.inner.with_status_mut(0, |s| {
        s.tcp.active_wire = 0;
        s.tcp.fallback_rtt_ewma = vec![Some(Duration::from_millis(200))];
    });

    let order: Vec<usize> = manager
        .tcp_candidates(&target)
        .await
        .iter()
        .map(|c| c.index)
        .collect();
    assert_eq!(
        order.first().copied(),
        Some(0),
        "with up-a back on its 10 ms primary wire it must outrank up-b; got {order:?}",
    );
}
