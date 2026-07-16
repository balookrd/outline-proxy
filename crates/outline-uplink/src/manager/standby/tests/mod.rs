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
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TransportMode,
    UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
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

    assert_eq!(
        manager.tcp_dial_mode_for(&candidate, false).await,
        TransportMode::WsH3,
        "an ordinary dial asks for the configured carrier when nothing is capped",
    );
    assert_eq!(
        manager.tcp_dial_mode_for(&candidate, true).await,
        TransportMode::WsH3,
        "so does a migration dial — the bypass is a no-op without a cap",
    );
}

#[tokio::test]
async fn migration_dial_ignores_the_cap_the_carrier_death_just_installed() {
    let manager = manager();
    let candidate = candidate();

    // The carrier death that triggers a migration is reported as a runtime
    // failure first, which caps this uplink h3 -> h2 for the next 60s.
    let error = h3_connection_collapse();
    manager.extend_mode_downgrade(
        0,
        TransportKind::Tcp,
        ModeDowngradeTrigger::RuntimeFailure(&error),
    );

    assert_eq!(
        manager.tcp_dial_mode_for(&candidate, false).await,
        TransportMode::WsH2,
        "an ordinary dial must still honour the cap — that is what it is for",
    );
    assert_eq!(
        manager.tcp_dial_mode_for(&candidate, true).await,
        TransportMode::WsH3,
        "the migration dial must ask for h3 anyway: honouring the cap here pins \
         the rescued flow to TCP-over-TCP for the rest of its life",
    );
}
