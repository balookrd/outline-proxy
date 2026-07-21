use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;

use super::*;
use outline_uplink::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TransportMode,
    UplinkConfig, VlessUdpMuxLimits, WsProbeConfig,
};
use tokio::net::UdpSocket;

fn probe_disabled() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(5),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 1,
        attempts: 1,
        skip_when_active: true,
        liveness_interval: Duration::from_secs(300),
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
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
        shared_resume: false,
        sticky_ttl: Duration::from_secs(300),
        hysteresis: Duration::from_millis(50),
        failure_cooldown: Duration::from_secs(10),
        tcp_chunk0_failover_timeout: Duration::from_secs(10),
        warm_standby_tcp: 0,
        warm_standby_udp: 0,
        rtt_ewma_alpha: 0.25,
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
        tcp_mid_session_retry_overflow_policy: outline_uplink::OverflowPolicy::Soft,
        tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
        tcp_symmetric_replay_enabled: false,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        bypass_when_down: false,
    }
}

/// An `ws_h3`-configured uplink whose carrier URL points at `port` on
/// loopback. Nothing listens there over TCP: an `ws_h2` dial can only fail,
/// while an `ws_h3` dial reaches for QUIC and therefore puts a UDP datagram
/// on the wire first — which is what the test observes.
fn h3_uplink_on(port: u16) -> UplinkConfig {
    UplinkConfig {
        name: "u1".to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(format!("wss://127.0.0.1:{port}/test").parse().unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH3,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH3,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
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
        padding: None,
        shuffle_timer: None,
    }
}

/// The shape of error that collapses a shared H3 carrier in the field. Fed
/// through the public runtime-failure entry point so the cap is installed by
/// the real writer rather than a test backdoor.
fn h3_connection_collapse() -> anyhow::Error {
    anyhow!(
        "websocket read failed: IO error: Connection error: Remote error: \
         ApplicationClose: H3_INTERNAL_ERROR"
    )
}

/// The mid-session retry redial must ask for the uplink's **configured**
/// carrier, not the mode-downgrade cap that the carrier death installed.
///
/// The trap this guards against: a shared H3 carrier dies, taking every
/// session on it down at once. Somebody — the standby refill loop, a TUN flow
/// on the same manager, a sibling session whose retry failed, the probe loop —
/// reports that death as a runtime failure, which caps the uplink `ws_h3` →
/// `ws_h2` for `mode_downgrade_secs`. A retry that honours the cap hands the
/// rescued session a TCP-over-TCP carrier, and nothing ever migrates a live
/// session back up, so it crawls for the rest of its life.
///
/// Observation without a server: `ws_h3` rides QUIC, so a dial that asks for
/// it emits a UDP datagram (the QUIC Initial) before anything else. `ws_h2`
/// rides TCP and never touches UDP. A datagram arriving on the carrier port is
/// therefore proof the dial asked for h3 — and its absence, proof it asked for
/// the capped h2.
#[tokio::test]
async fn mid_session_retry_dial_ignores_the_cap_the_carrier_death_installed() {
    // Bind UDP first so the port is ours, then point the uplink at it. Nothing
    // answers: the QUIC handshake never completes, which is fine — the test
    // only needs to see the attempt leave.
    let carrier = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = carrier.local_addr().unwrap().port();
    let quic_initials = Arc::new(AtomicUsize::new(0));
    let quic_initials_for_task = Arc::clone(&quic_initials);
    let carrier_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while carrier.recv_from(&mut buf).await.is_ok() {
            quic_initials_for_task.fetch_add(1, AtomicOrdering::SeqCst);
        }
    });

    let uplink = h3_uplink_on(port);
    let uplinks =
        UplinkManager::new_for_test("main", vec![uplink.clone()], probe_disabled(), lb()).unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };

    // The carrier death that triggers the retry caps this uplink h3 -> h2.
    let error = h3_connection_collapse();
    uplinks.note_advanced_mode_dial_failure(0, TransportKind::Tcp, &error);
    assert_eq!(
        uplinks.effective_tcp_mode(0).await,
        TransportMode::WsH2,
        "precondition: the runtime failure must have capped the uplink to h2 — \
         without an active cap this test proves nothing"
    );

    let target = TargetAddr::Domain("example.com".to_string(), 443);
    let redial = tokio::spawn(async move {
        let _ = redial_for_mid_session_retry(
            &uplinks,
            &candidate,
            &target,
            0,
            false,
            0,
            Some(SessionId::from_bytes([7u8; 16])),
        )
        .await;
    });

    // Poll rather than await the dial: with nothing answering, the h3 attempt
    // sits in its handshake timeout, and the datagram is the whole point.
    let mut saw_quic = false;
    for _ in 0..100 {
        if quic_initials.load(AtomicOrdering::SeqCst) > 0 {
            saw_quic = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    redial.abort();
    carrier_task.abort();

    assert!(
        saw_quic,
        "mid-session retry redial sent no QUIC Initial, so it asked for the capped \
         ws_h2 carrier: the rescued session would ride TCP-over-TCP for the rest of \
         its life. It must ask for the configured ws_h3 and let connect_transport \
         fall back inline if the carrier really is dead."
    );
}
