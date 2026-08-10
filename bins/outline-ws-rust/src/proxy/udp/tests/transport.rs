use std::sync::Arc as StdArc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tokio_tungstenite::accept_async;
use url::Url;

use outline_transport::{TransportMode, UdpResumeStore, UdpSessionTransport, UdpWsTransport};
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
        tcp_symmetric_replay_enabled: true,
        tcp_symmetric_replay_max_bytes: 1_048_576,
        tun_suppress_icmp_reply_when_down: false,
        tun_icmp_liveness_window: None,
        bypass_when_down: false,
        reselect_at: Vec::new(),
        reselect_interval: None,
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

    reconcile_global_udp_transport(&manager, &active, None, &UdpResumeStore::private())
        .await
        .expect("reconcile against the current active must succeed");
    assert_eq!(active.load().index, 0, "no switch happened, so the transport must be untouched");
    assert_eq!(dials.load(Ordering::SeqCst), 0, "an in-sync reconcile must not dial");

    // Operator switches the active uplink to up-b. The next datagram's reconcile
    // must migrate the session's transport onto it.
    manager.set_active_uplink_by_name("up-b", None, false).await.unwrap();
    reconcile_global_udp_transport(&manager, &active, None, &UdpResumeStore::private())
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

/// A WS upstream that records the *order* of connection opens and closes, which
/// is the only thing that distinguishes a redial that can resume from one that
/// cannot.
async fn spawn_ordered_ws_server()
-> (Url, StdArc<std::sync::Mutex<Vec<&'static str>>>, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: StdArc<std::sync::Mutex<Vec<&'static str>>> =
        StdArc::new(std::sync::Mutex::new(Vec::new()));
    let log_in_task = StdArc::clone(&log);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            let log = StdArc::clone(&log_in_task);
            tokio::spawn(async move {
                let Ok(ws) = accept_async(stream).await else { return };
                log.lock().unwrap().push("open");
                use futures_util::StreamExt as _;
                let (_sink, mut read) = ws.split();
                while read.next().await.transpose().ok().flatten().is_some() {}
                log.lock().unwrap().push("close");
            });
        }
    });
    (Url::parse(&format!("ws://{addr}/udp")).unwrap(), log, task)
}

async fn await_log_len(log: &StdArc<std::sync::Mutex<Vec<&'static str>>>, len: usize) {
    for _ in 0..600 {
        if log.lock().unwrap().len() >= len {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {len} connection events, got {:?}", log.lock().unwrap());
}

/// A repoint the session is meant to survive must **retire the old carrier
/// before dialling the new one**.
///
/// The server parks a datagram session only once its stream has closed, so a
/// redial that goes out first looks the association's id up against a still-live
/// session, is told `miss-unknown`, and is handed a fresh upstream on a fresh
/// source port. Reconcile used to dial first and close afterwards, so *every*
/// strict repoint silently lost NAT continuity no matter how resume was
/// configured.
#[tokio::test]
async fn a_migrating_reconcile_retires_the_old_carrier_before_redialling() {
    let (udp_url, log, server) = spawn_ordered_ws_server().await;
    let manager = outline_uplink::UplinkManager::new_for_test(
        "main",
        vec![strict_uplink("up-a", &udp_url), strict_uplink("up-b", &udp_url)],
        probe_disabled(),
        LoadBalancingConfig {
            shared_resume: true,
            ..strict_global_lb()
        },
    )
    .unwrap();
    manager.set_active_uplink_by_name("up-a", None, false).await.unwrap();

    let store = UdpResumeStore::private();
    let initial = select_udp_transport(&manager, None, None, &store).await.unwrap();
    let active = ArcSwap::from_pointee(initial);
    await_log_len(&log, 1).await;

    let (_index, applied_soft) =
        manager.set_active_uplink_by_name("up-b", None, true).await.unwrap();
    assert!(applied_soft, "a shared_resume group honours the soft bit");

    reconcile_global_udp_transport(&manager, &active, None, &store)
        .await
        .expect("reconcile must move the association to the new active");
    assert_eq!(active.load().index, 1);
    await_log_len(&log, 3).await;

    assert_eq!(
        &log.lock().unwrap()[..3],
        &["open", "close", "open"],
        "the old carrier must close before the redial, or the server has nothing \
         parked for the id the redial presents",
    );
    server.abort();
}

/// Negative control: on a **drain** the ordering is deliberately left alone.
/// There is no resume to protect, and closing first would leave the association
/// with no carrier at all if the replacement dial then failed.
///
/// Without this the rule above would also be satisfied by "always close first",
/// which is a different (and worse) behaviour.
#[tokio::test]
async fn a_draining_reconcile_keeps_the_old_carrier_until_the_redial_lands() {
    let (udp_url, log, server) = spawn_ordered_ws_server().await;
    let manager = outline_uplink::UplinkManager::new_for_test(
        "main",
        vec![strict_uplink("up-a", &udp_url), strict_uplink("up-b", &udp_url)],
        probe_disabled(),
        LoadBalancingConfig {
            shared_resume: true,
            ..strict_global_lb()
        },
    )
    .unwrap();
    manager.set_active_uplink_by_name("up-a", None, false).await.unwrap();

    let store = UdpResumeStore::private();
    let initial = select_udp_transport(&manager, None, None, &store).await.unwrap();
    let active = ArcSwap::from_pointee(initial);
    await_log_len(&log, 1).await;

    // Hard switch: an operator draining the node.
    manager.set_active_uplink_by_name("up-b", None, false).await.unwrap();
    reconcile_global_udp_transport(&manager, &active, None, &store)
        .await
        .expect("reconcile must move the association to the new active");
    assert_eq!(active.load().index, 1);
    await_log_len(&log, 3).await;

    assert_eq!(
        &log.lock().unwrap()[..3],
        &["open", "open", "close"],
        "a drain dials the replacement before letting the old carrier go",
    );
    server.abort();
}
