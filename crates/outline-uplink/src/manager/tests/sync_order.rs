//! Deterministic cross-node re-selection order: slot keys, seed, order, pick.
//!
//! Fixture style mirrors `manager/tests/reselect.rs` (the two modules are
//! siblings and share no private helpers, so `uplink()` / `probe()` / `lb()`
//! are duplicated here): minimal single-wire uplinks, an `active_passive`
//! load-balancing config, and no live probing.

use std::time::Duration;

use tokio::time::Instant;
use url::Url;

use super::super::sync_order::{SlotKey, current_slot_key, previous_slot_key, sync_seed};
use crate::config::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TransportMode,
    UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::types::{TransportKind, UplinkManager};

const SLOTS: [(u8, u8); 2] = [(3, 20), (15, 0)];

#[test]
fn current_slot_key_picks_the_latest_slot_already_passed() {
    // 04:00 local — past 03:20, before 15:00.
    let key = current_slot_key(100, 4 * 3600, &SLOTS).expect("slots configured");
    assert_eq!(key, SlotKey { day_key: 100, slot: 0 });

    // 16:00 local — past both.
    let key = current_slot_key(100, 16 * 3600, &SLOTS).expect("slots configured");
    assert_eq!(key, SlotKey { day_key: 100, slot: 1 });
}

#[test]
fn current_slot_key_before_the_first_slot_belongs_to_yesterday() {
    // 01:00 local — today's 03:20 has not fired yet, so the decision in force
    // is still yesterday's last slot. Without this a node restarting after
    // midnight would compute a different key than one that kept running.
    let key = current_slot_key(100, 3600, &SLOTS).expect("slots configured");
    assert_eq!(key, SlotKey { day_key: 99, slot: 1 });
}

#[test]
fn current_slot_key_is_none_without_slots() {
    assert!(current_slot_key(100, 3600, &[]).is_none());
}

#[test]
fn previous_slot_key_walks_back_across_the_day_boundary() {
    let same_day = previous_slot_key(SlotKey { day_key: 100, slot: 1 }, &SLOTS);
    assert_eq!(same_day, SlotKey { day_key: 100, slot: 0 });

    let wrapped = previous_slot_key(SlotKey { day_key: 100, slot: 0 }, &SLOTS);
    assert_eq!(wrapped, SlotKey { day_key: 99, slot: 1 });
}

#[test]
fn sync_seed_is_stable_for_the_same_inputs() {
    let key = SlotKey { day_key: 100, slot: 0 };
    let a = sync_seed("main", &["nuxt", "nuxt2", "senko"], key);
    let b = sync_seed("main", &["nuxt", "nuxt2", "senko"], key);
    assert_eq!(a, b, "same inputs must produce the same seed on every node");
}

#[test]
fn sync_seed_separates_days_slots_groups_and_uplink_sets() {
    let base = sync_seed("main", &["nuxt", "nuxt2"], SlotKey { day_key: 100, slot: 0 });
    assert_ne!(base, sync_seed("main", &["nuxt", "nuxt2"], SlotKey { day_key: 101, slot: 0 }));
    assert_ne!(base, sync_seed("main", &["nuxt", "nuxt2"], SlotKey { day_key: 100, slot: 1 }));
    assert_ne!(base, sync_seed("russia", &["nuxt", "nuxt2"], SlotKey { day_key: 100, slot: 0 }));
    assert_ne!(
        base,
        sync_seed("main", &["nuxt", "nuxt2", "senko"], SlotKey { day_key: 100, slot: 0 })
    );
}

#[test]
fn sync_seed_does_not_confuse_concatenated_names() {
    // Without a separator "ab" + "c" and "a" + "bc" hash identically, which
    // would silently merge two different fleets into one sync domain.
    let key = SlotKey { day_key: 100, slot: 0 };
    assert_ne!(sync_seed("main", &["ab", "c"], key), sync_seed("main", &["a", "bc"], key));
}

#[tokio::test]
async fn sync_order_is_a_full_permutation_and_agrees_across_managers() {
    let names = vec![uplink("a"), uplink("b"), uplink("c")];
    let one = manager_sync(names.clone());
    let two = manager_sync(names);
    let key = SlotKey { day_key: 100, slot: 0 };

    let order = one.sync_order(key);
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, vec![0, 1, 2], "every uplink must appear exactly once");
    assert_eq!(order, two.sync_order(key), "two nodes must derive the same order");
}

#[tokio::test]
async fn sync_order_reshuffles_across_days() {
    let mgr = manager_sync(vec![uplink("a"), uplink("b"), uplink("c"), uplink("d")]);
    // A single day pair could coincide by chance even with a good seed, so
    // assert over a window: a week must not be one frozen order.
    let first = mgr.sync_order(SlotKey { day_key: 100, slot: 0 });
    let differs = (101..=107).any(|day| mgr.sync_order(SlotKey { day_key: day, slot: 0 }) != first);
    assert!(differs, "the order must depend on the day key");
}

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
        rtt_ewma_halflife: Duration::from_secs(300),
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
        reselect_sync: false,
    }
}

/// Strict `active_passive` group with `reselect_sync` on and every uplink
/// pre-marked TCP-healthy (global scope gates on TCP).
fn manager_sync(uplinks: Vec<UplinkConfig>) -> UplinkManager {
    let cfg = LoadBalancingConfig {
        reselect_at: vec![(3, 20)],
        reselect_sync: true,
        ..lb()
    };
    let mgr = UplinkManager::new_for_test("main", uplinks, probe(), cfg).unwrap();
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(true);
        });
    }
    mgr
}

/// The pick both nodes must reach: first healthy entry of the slot's order,
/// minus the previous slot's deterministic winner.
fn expected_pick(mgr: &UplinkManager, key: SlotKey) -> usize {
    let excluded = mgr
        .sync_order(previous_slot_key(key, &[(3, 20)]))
        .first()
        .copied()
        .expect("non-empty group");
    mgr.sync_order(key)
        .into_iter()
        .find(|&i| i != excluded)
        .expect("more than one uplink")
}

#[tokio::test]
async fn sync_pick_agrees_across_managers_and_skips_the_previous_winner() {
    let names = vec![uplink("a"), uplink("b"), uplink("c")];
    let one = manager_sync(names.clone());
    let two = manager_sync(names);
    let key = SlotKey { day_key: 100, slot: 0 };
    let now = Instant::now();

    let pick = one.sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now);
    assert_eq!(pick, Some(expected_pick(&one, key)));
    assert_eq!(
        pick,
        two.sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now),
        "independent nodes must reach the same pick"
    );
}

#[tokio::test]
async fn sync_pick_skips_an_unhealthy_leg() {
    let mgr = manager_sync(vec![uplink("a"), uplink("b"), uplink("c")]);
    let key = SlotKey { day_key: 100, slot: 0 };
    let now = Instant::now();
    let first = mgr
        .sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now)
        .unwrap();

    mgr.inner.with_status_mut(first, |status| {
        status.tcp.healthy = Some(false);
    });

    let after = mgr
        .sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now)
        .unwrap();
    assert_ne!(after, first, "a dead leg must not win its own slot");
}

#[tokio::test]
async fn sync_pick_drops_the_exclusion_rather_than_returning_nothing() {
    // Only the previously-winning uplink is healthy: both nodes must still
    // converge on it instead of reporting "no candidate" and drifting apart.
    let mgr = manager_sync(vec![uplink("a"), uplink("b")]);
    let key = SlotKey { day_key: 100, slot: 0 };
    let now = Instant::now();
    let excluded = mgr.sync_order(previous_slot_key(key, &[(3, 20)]))[0];
    for index in 0..mgr.uplinks().len() {
        if index != excluded {
            mgr.inner.with_status_mut(index, |status| {
                status.tcp.healthy = Some(false);
            });
        }
    }

    let pick = mgr.sync_pick(key, TransportKind::Tcp, RoutingScope::Global, now);
    assert_eq!(pick, Some(excluded), "advisory exclusion must yield to reality");
}

#[tokio::test]
async fn sync_pick_returns_none_when_everything_is_down() {
    let mgr = manager_sync(vec![uplink("a"), uplink("b")]);
    for index in 0..mgr.uplinks().len() {
        mgr.inner.with_status_mut(index, |status| {
            status.tcp.healthy = Some(false);
        });
    }
    let pick = mgr.sync_pick(
        SlotKey { day_key: 100, slot: 0 },
        TransportKind::Tcp,
        RoutingScope::Global,
        Instant::now(),
    );
    assert_eq!(pick, None);
}
