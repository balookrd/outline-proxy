//! Which carrier a fresh / migration dial asks for.
//!
//! Regression cover for the field failure where every TUN TCP flow rescued
//! from a collapsed H3 carrier landed on `ws_h2` and stayed there: the carrier
//! death that triggers the migration also caps the uplink's mode one rank down
//! (`ws_h3` → `ws_h2`) for `mode_downgrade_duration`, so a migration dial that
//! honours the cap is guaranteed the TCP-over-TCP carrier — and nothing ever
//! migrates a live flow back up. Prod bore this out: migrated flows took h2 in
//! 45–63% of dials against 0.04–0.36% for ordinary ones.

use std::time::Duration;

use url::Url;

use crate::config::{
    CipherKind, FallbackTransport, LoadBalancingConfig, LoadBalancingMode, ProbeConfig,
    RoutingScope, TransportMode, UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use crate::manager::mode_downgrade::ModeDowngradeTrigger;
use crate::types::{TransportKind, UplinkCandidate, UplinkManager};

/// Single-wire SS uplink dialing `ws_h3` — the shape of the field uplink whose
/// shared H3 carrier collapses.
fn h3_uplink() -> UplinkConfig {
    UplinkConfig {
        name: "nuxt".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse("wss://live.example.com/primary/tcp").unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: Some(Url::parse("wss://live.example.com/primary/udp").unwrap()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH3,
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
        health_weighted_selection: false,
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

fn probe_cfg() -> ProbeConfig {
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

fn manager() -> UplinkManager {
    UplinkManager::new_for_test("main", vec![h3_uplink()], probe_cfg(), lb()).unwrap()
}

fn candidate() -> UplinkCandidate {
    UplinkCandidate { index: 0, uplink: h3_uplink().into() }
}

/// The exact runtime error the field logs show collapsing the shared carrier.
fn h3_connection_collapse() -> anyhow::Error {
    anyhow::anyhow!(
        "websocket read failed: IO error: Connection error: Remote error: \
         ApplicationClose: H3_INTERNAL_ERROR"
    )
}

#[tokio::test]
async fn without_a_cap_both_dial_kinds_ask_for_the_configured_carrier() {
    let manager = manager();
    let candidate = candidate();
    let spec = crate::WireSpec::of(&candidate.uplink, 0).unwrap();

    assert_eq!(
        manager.tcp_dial_mode_for(&candidate, &spec, false).await,
        TransportMode::WsH3,
        "an ordinary dial asks for the configured carrier when nothing is capped",
    );
    assert_eq!(
        manager.tcp_dial_mode_for(&candidate, &spec, true).await,
        TransportMode::WsH3,
        "so does a migration dial — the bypass is a no-op without a cap",
    );
}

#[tokio::test]
async fn migration_dial_ignores_the_cap_the_carrier_death_just_installed() {
    let manager = manager();
    let candidate = candidate();
    let spec = crate::WireSpec::of(&candidate.uplink, 0).unwrap();

    // The carrier death that triggers a migration is reported as a runtime
    // failure first, which caps this uplink h3 -> h2 for the next 60s.
    let error = h3_connection_collapse();
    manager.extend_mode_downgrade(
        0,
        TransportKind::Tcp,
        ModeDowngradeTrigger::RuntimeFailure(&error),
    );

    assert_eq!(
        manager.tcp_dial_mode_for(&candidate, &spec, false).await,
        TransportMode::WsH2,
        "an ordinary dial must still honour the cap — that is what it is for",
    );
    assert_eq!(
        manager.tcp_dial_mode_for(&candidate, &spec, true).await,
        TransportMode::WsH3,
        "the migration dial must ask for h3 anyway: honouring the cap here pins \
         the rescued flow to TCP-over-TCP for the rest of its life",
    );
}

/// An SS fallback wire whose carrier is `url` — same shape regardless of
/// whether `url` is a real listener or a closed port, since the caller
/// decides what happens when it is actually dialed.
fn fallback_wire_at(url: &Url) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(url.clone()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(url.clone()),
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

/// An SS uplink whose primary is `closed_url` and whose two fallback wires
/// are `wire1_url` (wire 1) and `wire2_url` (wire 2).
fn uplink_with_two_fallbacks(closed_url: &Url, wire1_url: &Url, wire2_url: &Url) -> UplinkConfig {
    UplinkConfig {
        name: "fallback-wire-test".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(closed_url.clone()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(closed_url.clone()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "shared".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: vec![fallback_wire_at(wire1_url), fallback_wire_at(wire2_url)],
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

/// A TCP port that was bound then immediately dropped, so a dial against it
/// fails fast (connection refused) instead of hanging on real network I/O.
async fn closed_port_url() -> Url {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let url = Url::parse(&format!("ws://{}/tcp", listener.local_addr().unwrap())).unwrap();
    drop(listener);
    url
}

/// An SS uplink with two fallback wires (wire 1, wire 2): the primary and
/// wire 1 point at closed ports (so a dial can never wander onto them), wire
/// 2 points at `wire2_url` — used by the fallback-wire attribution test,
/// which needs the wire-2 dial to actually succeed against a live mock
/// server so the post-dial bookkeeping (RTT EWMA, loss probe) really runs
/// rather than bailing out at `connect_transport`'s `?`.
pub(super) async fn sample_manager_with_live_wire_two(wire2_url: Url) -> UplinkManager {
    let closed_url = closed_port_url().await;
    let uplink = uplink_with_two_fallbacks(&closed_url, &closed_url, &wire2_url);
    UplinkManager::new_for_test("test", vec![uplink], probe_cfg(), lb()).unwrap()
}

/// A VLESS fallback wire whose carrier is `url` — never actually dialed by
/// [`sample_manager_with_vless_fallback`]'s tests, since building a VLESS-UDP
/// mux does not dial eagerly (it dials lazily per destination on first
/// packet). What matters here is the *shape*: transport, url and uuid must
/// come from this fallback, not from the parent uplink.
fn vless_fallback_wire_at(url: &Url, uuid: [u8; 16]) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Vless,
        tcp_ws_url: None,
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: Some(url.clone()),
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        vless_id: Some(uuid),
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: String::new(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

/// An SS uplink whose primary points at a closed port and whose one fallback
/// (wire 1) is VLESS pointing at `vless_url` — the shape of a fleet uplink
/// whose primary and first fallback are different transport families. The
/// primary being SS (not VLESS) is deliberate: it is what makes a regression
/// to reading `candidate.uplink.transport` instead of `spec.transport`
/// observable — the wrong read would route wire 1 through the SS dial path
/// against the closed primary port instead of building a VLESS mux.
fn uplink_with_vless_fallback(closed_url: &Url, vless_url: &Url, uuid: [u8; 16]) -> UplinkConfig {
    UplinkConfig {
        name: "vless-fallback-udp-test".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(closed_url.clone()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(closed_url.clone()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "shared".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: vec![vless_fallback_wire_at(vless_url, uuid)],
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

/// A manager with one uplink whose primary is SS (closed port) and whose
/// wire 1 is VLESS. `vless_url` need not be routable: the VLESS-UDP branch
/// builds a mux without dialing.
pub(super) async fn sample_manager_with_vless_fallback() -> UplinkManager {
    let closed_url = closed_port_url().await;
    let vless_url = Url::parse("wss://unroutable.invalid/vless").unwrap();
    let uuid = [7u8; 16];
    let uplink = uplink_with_vless_fallback(&closed_url, &vless_url, uuid);
    UplinkManager::new_for_test("test", vec![uplink], probe_cfg(), lb()).unwrap()
}

/// An [`UplinkCandidate`] for uplink `index` on `manager`. UDP dial-path
/// tests use this name for readability at call sites; the construction is
/// transport-agnostic and identical to
/// [`UplinkManager::tcp_candidates_for_test`], which it delegates to rather
/// than duplicating the pattern.
pub(super) async fn udp_candidate_for_test(
    manager: &UplinkManager,
    index: usize,
) -> UplinkCandidate {
    manager.tcp_candidates_for_test(index).await
}
