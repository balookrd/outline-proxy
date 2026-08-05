//! Weighted-random forced re-selection of the strict active uplink.
//!
//! Mirrors the fixture style of `manager/tests/active_wire.rs`: minimal
//! single-wire uplinks (no fallbacks), a `lb()` builder for the
//! `active_passive` load-balancing config, and seeded `StdRng` for
//! deterministic weighted picks.

use std::time::Duration;

use rand::SeedableRng;
use rand::rngs::StdRng;
use url::Url;

use crate::config::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TransportMode,
    UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::manager::reselect::{ReselectOutcome, due_slot, initial_last_fired};
use crate::types::{TransportKind, UplinkManager};

/// Single-wire uplink (no fallbacks), parametric in name so tests can build
/// distinguishable "a" / "b" / "c" candidates.
fn uplink(name: &str) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse(&format!("wss://host.example.com/{name}/tcp")).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(Url::parse(&format!("wss://host.example.com/{name}/udp")).unwrap()),
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
        fallbacks: vec![],
        shuffle_wires: false,
        carrier_downgrade: false,
        padding: None,
        shuffle_timer: None,
    }
}

/// UDP-incapable single-wire uplink (no `udp_ws_url`, no fallback at all —
/// so `supports_udp_any()` is false): the fixture the missing
/// `supports_transport_for_scope` filter regression needs, since every other
/// fixture in this file carries `udp_ws_url`.
fn uplink_no_udp(name: &str) -> UplinkConfig {
    UplinkConfig { udp_ws_url: None, ..uplink(name) }
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
        // Disabled: `initialize_strict_active_selection` would otherwise dial
        // real (unreachable) probe targets before the initial selection.
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
        loss_latency_penalty_k: 0.0,
        loss_latency_inflation_max: 4.0,
        loss_sample_interval: Duration::from_secs(30),
        loss_sample_min_packets: 50,
        loss_ewma_alpha: 0.2,
        failure_penalty: Duration::from_millis(500),
        failure_penalty_max: Duration::from_secs(30),
        failure_penalty_halflife: Duration::from_secs(60),
        mode_downgrade_duration: Duration::from_secs(60),
        carrier_degraded_failover: None,
        loss_failover_ratio: 0.0,
        loss_failover_duration: None,
        runtime_failure_window: Duration::from_secs(60),
        chunk0_failure_window: Duration::from_secs(300),
        global_udp_strict_health: false,
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: None,
        warm_probe_keepalive_interval: None,
        auto_failback: false,
        health_weighted_selection: true,
        tun_wire_dial: false,
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
        reselect_at: Vec::new(),
        reselect_interval: None,
    }
}

/// `active_active` group — reselect must refuse to touch it (Task 2 only
/// operates on the strict `active_passive` slot).
fn manager_active_active(uplinks: Vec<UplinkConfig>) -> UplinkManager {
    let cfg = LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        ..lb()
    };
    UplinkManager::new_for_test("main", uplinks, probe(), cfg).unwrap()
}

/// Strict `active_passive` / global-scope group with every uplink pre-marked
/// TCP-healthy (probe is disabled in these fixtures, and `selection_health`
/// under `RoutingScope::Global` gates purely on TCP health — see
/// `crate::selection::selection_health`). Without this, every candidate would
/// read `healthy == None` and the eligibility filter in `reselect_active_uplink`
/// would reject the whole group, which is not what these tests exercise.
fn manager_strict(uplinks: Vec<UplinkConfig>) -> UplinkManager {
    let mgr = UplinkManager::new_for_test("main", uplinks, probe(), lb()).unwrap();
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(true);
        });
    }
    mgr
}

/// Strict `active_passive` / **per-uplink**-scope group with every uplink
/// pre-marked healthy on both transports. Unlike `manager_strict` (global
/// scope, TCP-only gate), `PerUplink` gates TCP and UDP independently, so
/// both need seeding for the fixture to start from "everyone eligible".
fn manager_strict_per_uplink(uplinks: Vec<UplinkConfig>) -> UplinkManager {
    let cfg = LoadBalancingConfig {
        routing_scope: RoutingScope::PerUplink,
        ..lb()
    };
    let mgr = UplinkManager::new_for_test("main", uplinks, probe(), cfg).unwrap();
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(true);
            status.udp.healthy = Some(true);
        });
    }
    mgr
}

fn manager_strict_shared_resume(uplinks: Vec<UplinkConfig>) -> UplinkManager {
    let mgr = UplinkManager::new_for_test(
        "main",
        uplinks,
        probe(),
        LoadBalancingConfig { shared_resume: true, ..lb() },
    )
    .unwrap();
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(true);
        });
    }
    mgr
}

#[tokio::test]
async fn skipped_outside_active_passive() {
    let mgr = manager_active_active(vec![uplink("a"), uplink("b")]);
    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", true, &mut rng).await;
    assert!(matches!(outcome, ReselectOutcome::Skipped { .. }), "got {outcome:?}");
}

#[tokio::test]
async fn forced_roll_moves_off_the_active() {
    let mgr = manager_strict(vec![uplink("a"), uplink("b"), uplink("c")]);
    mgr.initialize_strict_active_selection().await; // active := index 0 ("a")
    let before = mgr.active_uplinks_snapshot().global;
    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
    let ReselectOutcome::Switched { to, soft, .. } = outcome else {
        panic!("expected Switched, got {outcome:?}");
    };
    assert!(!soft, "shared_resume off => soft clamped to false");
    let after = mgr.active_uplinks_snapshot().global;
    assert_ne!(after, before, "forced roll must move the active slot");
    assert_eq!(mgr.uplinks()[after.unwrap()].name, to);
}

#[tokio::test]
async fn single_uplink_group_has_no_candidate() {
    let mgr = manager_strict(vec![uplink("a")]);
    mgr.initialize_strict_active_selection().await;
    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", true, &mut rng).await;
    assert!(matches!(outcome, ReselectOutcome::NoCandidate), "got {outcome:?}");
}

#[tokio::test]
async fn admin_disabled_uplinks_are_excluded() {
    let mgr = manager_strict(vec![uplink("a"), uplink("b"), uplink("c")]);
    mgr.initialize_strict_active_selection().await; // active = "a"
    mgr.set_uplink_enabled_by_name("b", false).await.unwrap();
    // Only "c" remains eligible — every seed must land on it.
    for seed in 0..20 {
        let mut rng = StdRng::seed_from_u64(seed);
        // Re-activate "a" so the exclusion set stays {a(active), b(disabled)}.
        mgr.set_active_uplink_by_name("a", None, false).await.unwrap();
        // `set_active_uplink_by_name` is a manual-switch clean-slate signal:
        // it resets EVERY uplink's status (see `reset_all_uplink_statuses`),
        // wiping the probe health this fixture staged. Re-stamp it via the
        // existing `test_set_tcp_health` hook before every reselect — the
        // eligibility filter must not be weakened to route around this.
        for index in 0..mgr.uplinks().len() {
            mgr.test_set_tcp_health(index, true, 10).await;
        }
        let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
        let ReselectOutcome::Switched { to, .. } = outcome else { panic!("got {outcome:?}") };
        assert_eq!(to, "c");
    }
}

#[tokio::test]
async fn per_uplink_scope_rolls_each_transport_independently() {
    let mgr = manager_strict_per_uplink(vec![uplink("a"), uplink("b"), uplink("c")]);
    mgr.initialize_strict_active_selection().await; // tcp := udp := index 0 ("a")

    // TCP: only "b" (index 1) is eligible — "c" is marked TCP-unhealthy.
    mgr.inner
        .with_status_mut(2, |status| status.tcp.healthy = Some(false));
    // UDP: only "c" (index 2) is eligible — "b" is marked UDP-unhealthy.
    mgr.inner
        .with_status_mut(1, |status| status.udp.healthy = Some(false));

    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
    assert!(matches!(outcome, ReselectOutcome::Switched { .. }), "got {outcome:?}");

    let snapshot = mgr.active_uplinks_snapshot();
    assert_eq!(
        mgr.uplinks()[snapshot.tcp.unwrap()].name,
        "b",
        "TCP slot must land on the only TCP-eligible uplink"
    );
    assert_eq!(
        mgr.uplinks()[snapshot.udp.unwrap()].name,
        "c",
        "UDP slot must land on the only UDP-eligible uplink"
    );
}

#[tokio::test]
async fn per_uplink_scope_skips_transport_without_candidate() {
    let mgr = manager_strict_per_uplink(vec![uplink("a"), uplink("b"), uplink("c")]);
    mgr.initialize_strict_active_selection().await; // tcp := udp := index 0 ("a")

    // UDP: neither "b" nor "c" is eligible — TCP keeps both.
    mgr.inner
        .with_status_mut(1, |status| status.udp.healthy = Some(false));
    mgr.inner
        .with_status_mut(2, |status| status.udp.healthy = Some(false));

    let before = mgr.active_uplinks_snapshot();
    let mut rng = StdRng::seed_from_u64(1);
    let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
    assert!(matches!(outcome, ReselectOutcome::Switched { .. }), "got {outcome:?}");

    let after = mgr.active_uplinks_snapshot();
    assert_ne!(after.tcp, before.tcp, "TCP slot must have moved off the active");
    assert_eq!(
        after.udp, before.udp,
        "UDP slot must stay unchanged when no eligible candidate exists"
    );
}

/// A UDP-incapable uplink (no `udp_ws_url`, no UDP-capable fallback) must be
/// excludable from the TCP draw normally but MUST NEVER win the UDP draw: the
/// draw is missing the `supports_transport_for_scope` filter every other
/// candidate builder applies (`manager/candidates.rs`), so a UDP-incapable
/// uplink could otherwise be handed the strict UDP active slot merely because
/// its status happens to read UDP-healthy (e.g. via `fallback_bootstrap_allowed`
/// or a stale manual health stamp) — publishing an uplink that cannot carry
/// UDP to the snapshot, gauge, state file and dashboard.
#[tokio::test]
async fn udp_incapable_candidate_wins_tcp_draw_but_never_udp_draw() {
    let mgr = manager_strict_per_uplink(vec![uplink("a"), uplink_no_udp("no-udp")]);
    mgr.initialize_strict_active_selection().await; // tcp := udp := index 0 ("a")

    for seed in 0..20 {
        let mut rng = StdRng::seed_from_u64(seed);
        let before = mgr.active_uplinks_snapshot();
        let outcome = mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await;
        assert!(matches!(outcome, ReselectOutcome::Switched { .. }), "got {outcome:?}");
        let after = mgr.active_uplinks_snapshot();

        assert_eq!(
            mgr.uplinks()[after.tcp.unwrap()].name,
            "no-udp",
            "the only non-active candidate must win the TCP draw"
        );
        assert_eq!(
            after.udp, before.udp,
            "the UDP-incapable uplink must never win the UDP draw, seed {seed}"
        );

        // Re-activate "a" on both transports for the next seed's exclusion set.
        mgr.set_active_uplink_by_name("a", None, false).await.unwrap();
        for index in 0..mgr.uplinks().len() {
            mgr.test_set_tcp_health(index, true, 10).await;
            mgr.test_set_udp_health(index, true, 10).await;
        }
    }
}

#[tokio::test]
async fn soft_bit_follows_shared_resume() {
    let mgr = manager_strict_shared_resume(vec![uplink("a"), uplink("b")]);
    mgr.initialize_strict_active_selection().await;
    let mut rng = StdRng::seed_from_u64(1);
    let ReselectOutcome::Switched { soft, .. } =
        mgr.reselect_active_uplink_with_rng("test", true, &mut rng).await
    else {
        panic!("expected Switched");
    };
    assert!(soft);
    assert_eq!(
        mgr.active_uplinks_snapshot().intent,
        crate::types::SwitchIntent::OperatorSoft,
        "published snapshot carries the operator's soft intent",
    );
}

#[tokio::test]
async fn penalised_candidate_is_picked_less_often() {
    // 3 uplinks, active = "a"; heavy uplink-level penalty on "b" (test hook).
    // Over ~2000 seeded trials "c" must win clearly more often than "b", but
    // "b" must still win sometimes (health_weight_floor keeps it reachable).
    let mut b_wins = 0u32;
    let mut c_wins = 0u32;
    for seed in 0..2000 {
        let mgr = manager_strict(vec![uplink("a"), uplink("b"), uplink("c")]);
        mgr.initialize_strict_active_selection().await;
        mgr.test_add_uplink_penalty(1, TransportKind::Tcp, 60);
        let mut rng = StdRng::seed_from_u64(seed);
        match mgr.reselect_active_uplink_with_rng("test", false, &mut rng).await {
            ReselectOutcome::Switched { to, .. } if to == "b" => b_wins += 1,
            ReselectOutcome::Switched { to, .. } if to == "c" => c_wins += 1,
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert!(c_wins > b_wins * 4, "penalty must bias away from b: b={b_wins} c={c_wins}");
    assert!(b_wins > 0, "floor keeps the penalised uplink reachable");
}

#[test]
fn due_slot_fires_within_tolerance_only() {
    let slots = [(3, 0), (10, 10)];
    // 03:00:00 exact and up to +90 s fire slot 0; before or beyond do not.
    assert_eq!(due_slot(700, 3 * 3600, &slots, None), Some(0));
    assert_eq!(due_slot(700, 3 * 3600 + 90, &slots, None), Some(0));
    assert_eq!(due_slot(700, 3 * 3600 - 1, &slots, None), None, "never early");
    assert_eq!(due_slot(700, 3 * 3600 + 91, &slots, None), None, "missed slot is skipped");
}

#[test]
fn due_slot_does_not_double_fire() {
    let slots = [(3, 0)];
    assert_eq!(due_slot(700, 3 * 3600 + 10, &slots, Some((700, 0))), None);
    // ...but the same slot fires again on the next day.
    assert_eq!(due_slot(701, 3 * 3600 + 10, &slots, Some((700, 0))), Some(0));
}

#[test]
fn due_slot_handles_multiple_slots_independently() {
    let slots = [(3, 0), (10, 10)];
    assert_eq!(due_slot(700, 10 * 3600 + 10 * 60, &slots, Some((700, 0))), Some(1));
}

#[test]
fn initial_last_fired_seeds_a_slot_currently_in_its_window() {
    let slots = [(3, 0), (10, 10)];
    // Starting up (or hot-applying) 10 s into slot 0's tolerance window must
    // treat that slot as already handled, so the very next tick does not
    // re-fire it.
    assert_eq!(initial_last_fired(700, 3 * 3600 + 10, &slots), Some((700, 0)));
    // Right at the boundary (+90 s) still counts as "in the window".
    assert_eq!(initial_last_fired(700, 3 * 3600 + 90, &slots), Some((700, 0)));
}

#[test]
fn initial_last_fired_is_none_outside_any_window() {
    let slots = [(3, 0), (10, 10)];
    assert_eq!(initial_last_fired(700, 3 * 3600 - 1, &slots), None, "before the slot");
    assert_eq!(initial_last_fired(700, 3 * 3600 + 91, &slots), None, "past tolerance");
}

#[test]
fn initial_last_fired_is_none_for_empty_slots() {
    assert_eq!(initial_last_fired(700, 3 * 3600, &[]), None);
}
