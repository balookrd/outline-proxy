use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tokio_tungstenite::accept_async;
use url::Url;

use outline_transport::{TransportMode, UdpSessionTransport, UdpWsTransport};
use outline_uplink::{
    LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, UplinkConfig,
    UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
};
use shadowsocks_crypto::CipherKind;

use super::*;

#[tokio::test]
async fn replacing_active_udp_transport_closes_previous_reader() {
    let old_transport = Arc::new(UdpSessionTransport::Ss(
        UdpWsTransport::from_socket(
            UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
            CipherKind::Chacha20IetfPoly1305,
            "password",
            "test_old",
        )
        .unwrap(),
    ));
    let new_transport = Arc::new(UdpSessionTransport::Ss(
        UdpWsTransport::from_socket(
            UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
            CipherKind::Chacha20IetfPoly1305,
            "password",
            "test_new",
        )
        .unwrap(),
    ));
    let active_transport = ArcSwap::from_pointee(ActiveUdpTransport {
        index: 1,
        uplink_name: Arc::from("old"),
        up_counters: metrics::udp_flow_counters("up", "test", "old"),
        transport: Arc::clone(&old_transport),
    });

    let reader_transport = Arc::clone(&old_transport);
    let read_task = tokio::spawn(async move { reader_transport.read_packet().await });

    let previous_transport = replace_active_udp_transport_if_current(
        &active_transport,
        1,
        ActiveUdpTransport {
            index: 2,
            uplink_name: Arc::from("new"),
            up_counters: metrics::udp_flow_counters("up", "test", "new"),
            transport: Arc::clone(&new_transport),
        },
    )
    .expect("active transport should be replaced");
    close_udp_transport(previous_transport, "test_replace").await;

    let error = tokio::time::timeout(Duration::from_secs(1), async {
        read_task.await.unwrap().unwrap_err()
    })
    .await
    .unwrap();
    assert!(format!("{error:#}").contains("udp transport closed"));
    assert_eq!(active_transport.load().index, 2);
}

/// Mock WS server that completes the handshake and holds every accepted socket
/// open, so a UDP-over-WS dial against it succeeds. The counter reports how many
/// dials reached it.
async fn spawn_ws_server() -> (Url, StdArc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dials = StdArc::new(AtomicUsize::new(0));
    let dials_in_task = StdArc::clone(&dials);
    let task = tokio::spawn(async move {
        let mut live = Vec::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            dials_in_task.fetch_add(1, Ordering::SeqCst);
            match accept_async(stream).await {
                Ok(ws) => live.push(ws),
                Err(_) => break,
            }
        }
    });
    (Url::parse(&format!("ws://{addr}/udp")).unwrap(), dials, task)
}

fn strict_uplink(name: &str, udp_url: &Url) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ss,
        tcp_ws_url: Some(Url::parse(&format!("ws://{name}.invalid/tcp")).unwrap()),
        tcp_xhttp_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: Some(udp_url.clone()),
        udp_xhttp_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        ss_ws_url: None,
        ss_xhttp_url: None,
        ss_mode: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "s3cr3t_password".to_string(),
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

fn strict_global_lb() -> LoadBalancingConfig {
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
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        tun_icmp_liveness_window: None,
        bypass_when_down: false,
    }
}

fn probe_disabled() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(120),
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

/// A datagram sent through a session pinned to the previous active uplink must
/// still land on the new one after a strict (`active_passive`) switch.
///
/// The per-datagram reconcile now pre-checks the manager's published
/// active-uplink snapshot instead of taking its async RwLock on every packet.
/// The invariant that pre-check must not weaken: once the snapshot disagrees
/// with the pinned uplink, reconcile still rebuilds the transport on the new
/// active — otherwise a strict-scope switch would leave datagrams flowing
/// through the deactivated uplink.
#[tokio::test]
async fn strict_reconcile_switches_udp_transport_to_the_new_active() {
    let (udp_url, dials, server) = spawn_ws_server().await;
    let manager = outline_uplink::UplinkManager::new_for_test(
        "main",
        vec![strict_uplink("up-a", &udp_url), strict_uplink("up-b", &udp_url)],
        probe_disabled(),
        strict_global_lb(),
    )
    .unwrap();

    // Session pinned to up-a, which is also the active uplink: reconcile is a
    // no-op and must not dial anything.
    manager.set_active_uplink_by_name("up-a", None, false).await.unwrap();
    let active = ArcSwap::from_pointee(ActiveUdpTransport {
        index: 0,
        uplink_name: Arc::from("up-a"),
        up_counters: metrics::udp_flow_counters("up", "main", "up-a"),
        transport: Arc::new(UdpSessionTransport::Ss(
            UdpWsTransport::from_socket(
                UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
                CipherKind::Chacha20IetfPoly1305,
                "s3cr3t_password",
                "test_pinned",
            )
            .unwrap(),
        )),
    });

    reconcile_global_udp_transport(&manager, &active, None)
        .await
        .expect("reconcile against the current active must succeed");
    assert_eq!(active.load().index, 0, "no switch happened, so the transport must be untouched");
    assert_eq!(dials.load(Ordering::SeqCst), 0, "an in-sync reconcile must not dial");

    // Operator switches the active uplink to up-b. The next datagram's reconcile
    // must migrate the session's transport onto it.
    manager.set_active_uplink_by_name("up-b", None, false).await.unwrap();
    reconcile_global_udp_transport(&manager, &active, None)
        .await
        .expect("reconcile must rebuild the transport on the new active uplink");

    assert_eq!(
        active.load().index,
        1,
        "a strict-scope switch must move the session's UDP transport to the new active",
    );
    assert_eq!(&*active.load().uplink_name, "up-b");
    assert_eq!(dials.load(Ordering::SeqCst), 1, "the switch must dial the new active once");

    server.abort();
}
