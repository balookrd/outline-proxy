use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;

use super::*;
use outline_uplink::{
    CipherKind, FallbackTransport, LoadBalancingConfig, LoadBalancingMode, ProbeConfig,
    RoutingScope, TransportMode, UplinkConfig, VlessUdpMuxLimits, WsProbeConfig,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;
use tokio_tungstenite::accept_async;

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
        health_weighted_selection: false,
        tun_wire_dial: false,
        health_weight_floor: 0.05,
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
        tcp_mid_session_retry_buffer_bytes: 256 * 1024,
        tcp_mid_session_retry_budget: 1,
        tcp_mid_session_retry_overflow_policy: outline_uplink::OverflowPolicy::Soft,
        tcp_mid_session_retry_consume_timeout: Duration::from_secs(5),
        tcp_symmetric_replay_enabled: false,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        tun_icmp_liveness_window: None,
        bypass_when_down: false,
        reselect_at: Vec::new(),
        reselect_interval: None,
        reselect_sync: false,
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

/// A dial that presented no Session ID must never expect the v1 / v2 resume
/// control frames, however the server echoed the capabilities.
///
/// The server emits those frames only after a resume **hit**, which a dial
/// carrying no id cannot produce — while it echoes the capability bits back to
/// anyone who advertises them. Keying the expectation on the echo alone
/// therefore makes the reader eat the first 14 bytes of real payload as an
/// `"ORSM"` header and kill the session on the parse.
///
/// That is what stopped the SOCKS side from advertising v1 + v2 on its fresh
/// dials — which is the only thing that makes the server allocate the session's
/// downlink replay ring. The TUN path already gates on the id
/// (`outline_tun::tcp::engine::connect`); this pins the same rule here.
#[test]
fn a_dial_presenting_no_id_never_expects_resume_control_frames() {
    assert!(
        !expects_resume_control_frames(false, true),
        "no id presented means no resume hit is possible, so no control frame follows — \
         expecting one consumes real payload as a control header",
    );
    assert!(
        expects_resume_control_frames(true, true),
        "a redial that presented its id and got the capability confirmed must read the frames",
    );
    assert!(
        !expects_resume_control_frames(true, false),
        "a server that did not confirm the capability sends nothing to read",
    );
}

/// An SS fallback wire tagged by its own `addr`. Mirrors the parent uplink in
/// every other field, the same way `WireSetup::from_fallback` /
/// `WireSpec::from_fallback` share the parent's identity while taking their
/// transport shape from the fallback entry itself.
fn ss_fallback_wire_at(addr: std::net::SocketAddr) -> FallbackTransport {
    FallbackTransport {
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(format!("ws://{addr}/tcp").parse().unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
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
        password: "secret".to_string(),
        fwmark: None,
        ipv6_first: false,
        fingerprint_profile: None,
    }
}

/// A TCP port that was bound then immediately dropped, so a dial against it
/// fails fast (connection refused) instead of hanging on real network I/O —
/// used to make the primary wire reliably dead.
async fn dead_port_url() -> url::Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/tcp", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    drop(listener);
    url
}

fn ss_uplink_with_dead_primary(
    name: &str,
    dead_url: url::Url,
    fallback: FallbackTransport,
) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(dead_url),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
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
        fallbacks: vec![fallback],
        shuffle_wires: false,
        carrier_downgrade: true,
        padding: None,
        shuffle_timer: None,
    }
}

/// Characterisation test for the wire-fallback refactor (folding
/// `connect_tcp_uplink_inner`/`connect_tcp_fallback_fresh` onto the shared
/// `UplinkManager::dial_over_wires` loop). SOCKS has walked its full wire
/// chain unconditionally for as long as the chain has existed — this pins
/// that a primary that cannot be reached still lands the connection on the
/// fallback wire, reported accurately via `wire_index` and `source`, and
/// must stay green whether the loop is the hand-rolled one or the shared
/// one underneath.
///
/// The primary points at a bound-then-dropped port (instant connection
/// refused); the fallback is a live mock WebSocket server, real enough for
/// `do_tcp_ss_setup`'s SS branch to complete — it only needs the WS upgrade
/// to succeed and never waits on a server-side reply before returning.
#[tokio::test]
async fn socks_fallback_still_reports_the_wire_it_landed_on() {
    let dead_url = dead_port_url().await;

    let fallback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fallback_addr = fallback_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = fallback_listener.accept().await.unwrap();
        if let Ok(ws) = accept_async(stream).await {
            // Hold the accepted socket open long enough for the dial's SS
            // handshake (writer construction + initial target chunk) to
            // complete on the client side.
            let _ = shutdown_rx.await;
            drop(ws);
        }
    });

    let uplink = ss_uplink_with_dead_primary("u1", dead_url, ss_fallback_wire_at(fallback_addr));
    let uplinks =
        UplinkManager::new_for_test("main", vec![uplink.clone()], probe_disabled(), lb()).unwrap();
    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };
    let target = TargetAddr::Domain("example.test".to_string(), 443);

    let connected = connect_tcp_uplink(&uplinks, &candidate, &target)
        .await
        .expect("primary must fail fast and the fallback wire must connect");

    assert_ne!(connected.wire_index, 0, "must have landed on the fallback wire, not primary");
    assert_eq!(connected.source, TcpUplinkSource::FreshDial);

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("mock fallback server task must finish within the timeout")
        .unwrap();
}

/// The warm pool follows the active wire once `tun_wire_dial` is on, so the
/// SOCKS ingress must ask it for **the wire it is dialing**, not for wire 0.
/// Asking for 0 while the pool prewarms wire 1 is a guaranteed miss on every
/// session: the ingress paid for the prewarm and then dialed fresh anyway.
///
/// Fixture: dead primary, live fallback, `active_wire` primed to 1 through the
/// state machine's own API, `warm_standby_tcp = 1` and one synchronous
/// maintenance pass so the pool holds exactly one carrier — dialed on wire 1.
/// The mock server accepts once; a `FreshDial` verdict here would mean the
/// acquisition went around the pool.
#[tokio::test]
async fn socks_takes_the_warm_pool_of_the_active_wire() {
    let dead_url = dead_port_url().await;

    let fallback_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fallback_addr = fallback_listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = fallback_listener.accept().await.unwrap();
        if let Ok(ws) = accept_async(stream).await {
            let _ = shutdown_rx.await;
            drop(ws);
        }
    });

    let uplink = ss_uplink_with_dead_primary("u1", dead_url, ss_fallback_wire_at(fallback_addr));
    let uplinks = UplinkManager::new_for_test(
        "main",
        vec![uplink.clone()],
        probe_disabled(),
        LoadBalancingConfig {
            tun_wire_dial: true,
            warm_standby_tcp: 1,
            ..lb()
        },
    )
    .unwrap();

    // Prime the active wire through the same call `dial_over_wires` makes, so
    // the pool's own `standby_ctx` resolves to wire 1 (`min_failures = 1`).
    uplinks.record_wire_outcome(0, TransportKind::Tcp, 0, false, 2);
    assert_eq!(
        uplinks.active_wire(0, TransportKind::Tcp),
        1,
        "fixture setup: the pool must be prewarming the fallback wire",
    );
    uplinks.test_maintain_pool(0, TransportKind::Tcp).await;

    let candidate = UplinkCandidate { index: 0, uplink: uplink.into() };
    let target = TargetAddr::Domain("example.test".to_string(), 443);
    let connected = connect_tcp_uplink(&uplinks, &candidate, &target)
        .await
        .expect("the pooled carrier on wire 1 must serve this connection");

    assert_eq!(connected.wire_index, 1, "the active wire is the one dialed");
    assert_eq!(
        connected.source,
        TcpUplinkSource::Standby,
        "a pool prewarmed on wire 1 must be reachable from a wire-1 acquisition; \
         asking it about wire 0 is a permanent miss",
    );

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("mock fallback server task must finish within the timeout")
        .unwrap();
}
