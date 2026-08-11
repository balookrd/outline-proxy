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
        health_weighted_selection: weighted,
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

fn manager(weighted: bool) -> UplinkManager {
    UplinkManager::new_for_test("main", vec![three_wire_uplink()], probe(), lb(weighted)).unwrap()
}

/// Primary + three fallbacks = four wires, for the head-pin tests below where
/// three non-active wires need to appear, unordered, in the tail.
fn four_wire_uplink() -> UplinkConfig {
    let mut cfg = three_wire_uplink();
    cfg.fallbacks.push(ss_fallback("fb3"));
    cfg
}

fn manager_with_four_wires_and_health_weighting() -> UplinkManager {
    UplinkManager::new_for_test("main", vec![four_wire_uplink()], probe(), lb(true)).unwrap()
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
    // 18 additions saturate `value_secs` at 9.0s (18 * 0.5s), giving weight
    // `1 / (1 + 9.0/0.5) = 1/19 ≈ 0.0526` — strictly *above* `health_weight_floor`
    // (0.05), unlike a fully-saturated penalty (60 additions caps at
    // `failure_penalty_max` = 30s, clamping the weight down to the floor
    // exactly — see `reroll_leaves_active_wire_untouched_when_every_alternative_is_at_the_floor`,
    // which covers that case: the wire must then be excluded, not merely
    // rare). This wire stays a *candidate* whenever it isn't the active one,
    // just a heavily-deprioritised one.
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 0, 18);
    mgr.test_add_wire_penalty(0, TransportKind::Udp, 0, 18);
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
    assert!(
        tcp_hits[0] > 0,
        "but its weight, still strictly above health_weight_floor at this penalty level, \
         keeps it reachable: {tcp_hits:?}"
    );
}

/// New: repeated draws never return the wire that was active going into that
/// draw — the whole point of "reroll", for both the weighted and the plain
/// (`health_weighted_selection = false`) draw. Before the exclude-current
/// fix, a uniform (or weighted) draw over *every* wire landed back on the
/// active wire roughly `1/total_wires` of the time — observed on the fleet
/// as a `shuffle_timer` tick reporting `udp_wire = 0` when wire 0 was
/// already active.
#[tokio::test]
async fn reroll_never_returns_the_wire_that_was_active() {
    for weighted in [true, false] {
        let mgr = manager(weighted);
        let mut active_tcp = mgr.read_status_for_test(0).tcp.active_wire;
        let mut active_udp = mgr.read_status_for_test(0).udp.active_wire;
        for i in 0..500 {
            let (tcp_wire, udp_wire) =
                mgr.rotate_active_wire(0).expect("multi-wire uplink rerolls");
            assert_ne!(
                tcp_wire, active_tcp,
                "draw {i} (weighted={weighted}): reroll must not return the previously-active TCP wire"
            );
            assert_ne!(
                udp_wire, active_udp,
                "draw {i} (weighted={weighted}): reroll must not return the previously-active UDP wire"
            );
            active_tcp = tcp_wire;
            active_udp = udp_wire;
        }
    }
}

/// New: when every non-active wire's weight has decayed all the way down to
/// `health_weight_floor` (not merely *toward* it — see the doc comment on
/// `weighted_rotate_avoids_flaky_wire_but_not_entirely` for the distinction),
/// the reroll must leave that transport's active wire, pin and
/// failure-accounting completely untouched: `apply` must not run for that
/// transport at all.
#[tokio::test]
async fn reroll_leaves_active_wire_untouched_when_every_alternative_is_at_the_floor() {
    let mgr = manager(true);
    // Saturate wires 1 and 2 to `failure_penalty_max` (30s via 60
    // additions of 0.5s each), which clamps their weight down to exactly
    // `health_weight_floor` (0.05) — "every alternative parked at the
    // floor", the case the reroll must treat as "no live alternative".
    // Wire 0 (active, default) is left unpenalised.
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 1, 60);
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 2, 60);

    // Stage failure-accounting and a pin that a real reroll would clear —
    // the untouched-plane guarantee must hold even though the uplink is
    // "recently proven" (which would otherwise take the reset branch).
    mgr.inner.with_status_mut(0, |status| {
        status.tcp.active_wire_streak = 3;
        status.tcp.wires_failed_in_round = 1;
        status.tcp.consecutive_failures = 2;
        status.tcp.consecutive_runtime_failures = 4;
        status.tcp.chunk0_consecutive_failures = 1;
        status.tcp.last_any_wire_success = Some(tokio::time::Instant::now());
    });
    let before = mgr.read_status_for_test(0).tcp;

    let (tcp_wire, _udp_wire) = mgr.rotate_active_wire(0).expect("multi-wire uplink rerolls");

    assert_eq!(tcp_wire, 0, "no live TCP alternative: active wire must stay put");
    let after = mgr.read_status_for_test(0).tcp;
    assert_eq!(after.active_wire, 0);
    assert_eq!(
        after.active_wire_streak, before.active_wire_streak,
        "untouched plane: streak must not reset"
    );
    assert_eq!(
        after.wires_failed_in_round, before.wires_failed_in_round,
        "untouched plane: shuffle_wires round-progress must not reset"
    );
    assert_eq!(
        after.consecutive_failures, before.consecutive_failures,
        "untouched plane: probe failure streak must not reset"
    );
    assert_eq!(
        after.consecutive_runtime_failures, before.consecutive_runtime_failures,
        "untouched plane: runtime failure streak must not reset"
    );
    assert_eq!(
        after.chunk0_consecutive_failures, before.chunk0_consecutive_failures,
        "untouched plane: chunk0 failure streak must not reset"
    );
    assert_eq!(
        after.active_wire_pinned_until, before.active_wire_pinned_until,
        "untouched plane: no pin refresh"
    );
}

/// New: `health_weight_floor = 1.0` is a degenerate but validator-accepted
/// edge of the documented `[0, 1]` range — `penalty_weight`'s `.max(floor)`
/// clamps *every* wire's weight to exactly `1.0` at that setting, so a plain
/// `w > floor` candidate filter can never be true for any wire. Without the
/// `floor >= 1.0` fallback in `draw_reroll_wire`, every tick would find zero
/// candidates and the anti-DPI reroll would silently stop working forever —
/// the operator's only symptom two WARN lines per tick that read like "every
/// wire is unhealthy" rather than "this knob disabled the feature". Assert
/// the reroll keeps changing the active wire on every tick even at this
/// setting, with a heavily-penalised wire in the mix (to prove the fallback
/// really does ignore weight, not just coincidentally pick the same wires
/// weight would have anyway).
#[tokio::test]
async fn reroll_still_works_when_health_weight_floor_is_1_0() {
    let mgr = UplinkManager::new_for_test(
        "main",
        vec![three_wire_uplink()],
        probe(),
        LoadBalancingConfig { health_weight_floor: 1.0, ..lb(true) },
    )
    .unwrap();
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 1, 60);
    mgr.test_add_wire_penalty(0, TransportKind::Udp, 1, 60);

    let mut tcp_active = mgr.read_status_for_test(0).tcp.active_wire;
    let mut udp_active = mgr.read_status_for_test(0).udp.active_wire;
    for i in 0..200 {
        let (tcp_wire, udp_wire) = mgr
            .rotate_active_wire(0)
            .expect("multi-wire uplink rerolls even with a degenerate floor");
        assert_ne!(
            tcp_wire, tcp_active,
            "draw {i}: health_weight_floor = 1.0 must not freeze the TCP reroll"
        );
        assert_ne!(
            udp_wire, udp_active,
            "draw {i}: health_weight_floor = 1.0 must not freeze the UDP reroll"
        );
        tcp_active = tcp_wire;
        udp_active = udp_wire;
    }
}

/// New: TCP and UDP draw independently. Penalising every TCP alternative
/// down to the floor must not stop UDP (with healthy alternatives) from
/// rerolling — and vice versa is exercised implicitly by every other test
/// here that only ever inspects `tcp_wire`.
#[tokio::test]
async fn reroll_planes_are_independent_when_only_one_has_no_live_alternative() {
    let mgr = manager(true);
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 1, 60);
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 2, 60);
    let mut udp_active = mgr.read_status_for_test(0).udp.active_wire;

    // Looped, not a single draw: a single call only fails under a revert of
    // the exclude-current fix about a third of the time (the weighted draw
    // still favours wire 0 by chance even without the exclusion), so a
    // one-shot assertion here is a weak regression trap. 200 iterations
    // (the weighted sibling test above runs 3000 for the same reason) make a
    // revert fail reliably instead of flaking green.
    for i in 0..200 {
        let (tcp_wire, udp_wire) = mgr.rotate_active_wire(0).expect("multi-wire uplink rerolls");

        assert_eq!(tcp_wire, 0, "draw {i}: TCP has no live alternative and must stay on wire 0");
        assert_ne!(
            udp_wire, udp_active,
            "draw {i}: UDP has healthy alternatives and must still reroll despite TCP's plane being stuck"
        );
        udp_active = udp_wire;
    }
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

/// The warm-standby pool is prewarmed on the active wire (see `standby_ctx`),
/// so under health weighting the active wire must still lead the dial order
/// — otherwise the pool's prewarm is wasted on every session that draws a
/// different head. The tail stays a liveness-weighted permutation of
/// whatever remains.
#[tokio::test]
async fn the_active_wire_leads_the_health_weighted_order() {
    let mgr = manager_with_four_wires_and_health_weighting();
    mgr.test_set_active_wire(0, TransportKind::Tcp, 2);

    // Weighted order is random in its tail, so assert the invariant over
    // several draws rather than one: the head is pinned, the tail is a
    // permutation of everything else.
    for _ in 0..16 {
        let order = mgr.wire_dial_order(0, TransportKind::Tcp, 4);
        assert_eq!(
            order[0], 2,
            "the pool is warmed on the active wire, so it must be dialed first"
        );
        let mut rest = order[1..].to_vec();
        rest.sort_unstable();
        assert_eq!(rest, vec![0, 1, 3], "every other wire still appears exactly once");
    }
}

/// A stale active wire (e.g. left over from a config reload that shrank the
/// fallback chain) must not panic, drop a wire, or duplicate one — it just
/// leaves the weighted order untouched, same defensive posture as the
/// non-weighted branch's cap.
#[tokio::test]
async fn an_out_of_range_active_wire_does_not_break_the_order() {
    let mgr = manager_with_four_wires_and_health_weighting();
    mgr.test_set_active_wire(0, TransportKind::Tcp, 9);

    let order = mgr.wire_dial_order(0, TransportKind::Tcp, 4);

    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![0, 1, 2, 3],
        "a stale active wire must not drop or duplicate a wire"
    );
}

/// The pin yields to a penalty: liveness weighting exists precisely so new
/// sessions do not pile onto a wire that has been disconnecting, and pinning
/// a *penalised* active wire to the head unconditionally would defeat that
/// (see `weighted_order_demotes_flaky_wire_but_keeps_it_reachable`, which
/// would break under an unconditional pin). This is the direct pin-side
/// counterpart to that statistical test: with the active wire itself
/// penalised, it must not lead every draw.
#[tokio::test]
async fn a_penalised_active_wire_does_not_always_lead() {
    let mgr = manager_with_four_wires_and_health_weighting();
    mgr.test_set_active_wire(0, TransportKind::Tcp, 0);
    mgr.test_add_wire_penalty(0, TransportKind::Tcp, 0, 60);

    let trials = 500;
    let mut active_leads = 0u32;
    for _ in 0..trials {
        let order = mgr.wire_dial_order(0, TransportKind::Tcp, 4);
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2, 3], "the cascade still contains every wire");
        if order[0] == 0 {
            active_leads += 1;
        }
    }
    // A proportional bound, not `< trials`: the latter only rejects a literal
    // 500/500, so a half-broken predicate that still pinned the active wire
    // 400 times out of 500 would pass. With the pin correctly yielding, wire 0
    // is drawn at its own weight — `floor / (floor + 1 + 1 + 1)` =
    // `0.05 / 3.05` ≈ 1.6 %, i.e. ~8 of 500 — so `trials / 6` (83) sits far
    // above the honest rate and far below anything a surviving pin produces.
    // Mirrors `weighted_order_demotes_flaky_wire_but_keeps_it_reachable`'s
    // bound, which is the statistical counterpart to this test.
    assert!(
        active_leads < trials / 6,
        "a penalised active wire must not be pinned to the head: {active_leads}/{trials}"
    );
}
