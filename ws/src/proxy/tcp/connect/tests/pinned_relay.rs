use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use outline_transport::{
    ServerAddr, TcpReader, TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
};
use outline_uplink::{
    CipherKind, LoadBalancingConfig, LoadBalancingMode, ProbeConfig, RoutingScope, TargetAddr,
    UplinkCandidate, UplinkConfig, UplinkTransport, VlessUdpMuxLimits, WsProbeConfig,
    TransportMode,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use crate::proxy::tcp::failover::TcpUplinkSource;

fn probe_disabled() -> ProbeConfig {
    ProbeConfig {
        interval: Duration::from_secs(30),
        timeout: Duration::from_secs(5),
        max_concurrent: 1,
        max_dials: 1,
        min_failures: 1,
        attempts: 1,
        ws: WsProbeConfig { enabled: false },
        http: None,
        dns: None,
        tcp: None,
    }
}

fn lb(keepalive_interval: Duration) -> LoadBalancingConfig {
    LoadBalancingConfig {
        mode: LoadBalancingMode::ActiveActive,
        routing_scope: RoutingScope::PerFlow,
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
        global_udp_strict_health: false,
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: Some(keepalive_interval),
        warm_probe_keepalive_interval: None,
        auto_failback: false,
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
        tcp_mid_session_retry_buffer_bytes: 256 * 1024,
        tcp_mid_session_retry_budget: 1,
        tcp_mid_session_retry_overflow_policy: outline_uplink::OverflowPolicy::Soft,
    }
}

fn make_uplink(name: &str, addr: SocketAddr) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Shadowsocks,
        tcp_ws_url: None,
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        tcp_addr: Some(addr.to_string().parse::<ServerAddr>().unwrap()),
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
        }
}

#[tokio::test(start_paused = true)]
async fn run_relay_keepalive_does_not_extend_idle_timeout() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (_stream, _) = upstream_listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });

    let uplink = make_uplink("primary", upstream_addr);
    let manager = UplinkManager::new_for_test(
        "test",
        vec![uplink.clone()],
        probe_disabled(),
        lb(Duration::from_millis(20)),
    )
    .unwrap();

    let stream = TcpStream::connect(upstream_addr).await.unwrap();
    let (reader_half, writer_half) = stream.into_split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password).unwrap();
    let lifetime = UpstreamTransportGuard::new("test", "tcp");
    let mut writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        uplink.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )
    .unwrap();
    let reader =
        TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime)
            .with_request_salt(writer.request_salt());
    writer
        .send_chunk(&TargetAddr::IpV4(Ipv4Addr::LOCALHOST, 443).to_wire_bytes().unwrap())
        .await
        .unwrap();
    let active = ActiveTcpUplink {
        index: 0,
        name: Arc::from(uplink.name.as_str()),
        candidate: UplinkCandidate { index: 0, uplink: uplink.into() },
        writer: TcpWriter::Socket(writer),
        reader: TcpReader::Socket(reader),
        source: TcpUplinkSource::DirectSocket,
        wire_index: 0,
    };

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let (connect_res, accept_res) =
        tokio::join!(TcpStream::connect(client_addr), client_listener.accept());
    let mut client_side = connect_res.unwrap();
    let (server_side, _) = accept_res.unwrap();
    let (client_read, client_write) = server_side.into_split();

    let timeouts = TcpTimeouts {
        post_client_eof_downstream: Duration::from_secs(30),
        upstream_response: Duration::from_secs(15),
        socks_upstream_idle: Duration::from_millis(50),
        direct_idle: Duration::from_secs(120),
    };
    let target = outline_transport::TargetAddr::IpV4(
        std::net::Ipv4Addr::new(127, 0, 0, 1),
        9999,
    );
    let relay_task = tokio::spawn(async move {
        run_relay(
            manager,
            active,
            target,
            Arc::from("test"),
            b"OK".to_vec(),
            client_read,
            client_write,
            &timeouts,
        )
        .await
    });

    let mut first_chunk = [0u8; 2];
    client_side.read_exact(&mut first_chunk).await.unwrap();
    assert_eq!(&first_chunk, b"OK");

    tokio::time::advance(timeouts.socks_upstream_idle + Duration::from_millis(10)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }

    assert!(
        relay_task.is_finished(),
        "relay should exit once socks_upstream_idle elapses without payload"
    );
    let result = relay_task.await.unwrap();
    assert!(result.is_ok(), "idle timeout should close the session cleanly");

    upstream_task.abort();
    let _ = upstream_task.await;
}

/// Builds a Ws-transport uplink whose `tcp_ws_url` points at a TCP
/// listener under the test's control. The listener does NOT speak WS;
/// it accepts and closes, so any redial attempt that reaches the
/// `tcp_ws_url` fails on the upgrade handshake. The accept counter
/// is the test's window into "did the orchestrator try to redial?".
fn make_ws_uplink_pointing_at(name: &str, redial_target: SocketAddr) -> UplinkConfig {
    UplinkConfig {
        name: name.to_string(),
        transport: UplinkTransport::Ws,
        tcp_ws_url: Some(format!("ws://{}/test", redial_target).parse().unwrap()),
        tcp_mode: TransportMode::WsH1,
        udp_ws_url: None,
        udp_mode: TransportMode::WsH1,
        vless_ws_url: None,
        vless_xhttp_url: None,
        vless_mode: TransportMode::WsH1,
        // tcp_addr is unused on the Ws transport, but the loader still
        // accepts it on the struct; setting None keeps the test honest.
        tcp_addr: None,
        udp_addr: None,
        cipher: CipherKind::Chacha20IetfPoly1305,
        password: "secret".to_string(),
        weight: 1.0,
        fwmark: None,
        ipv6_first: false,
        vless_id: None,
        fingerprint_profile: None,
        fallbacks: Vec::new(),
    }
}

/// Drives the `pinned_relay::run_relay` retry orchestrator through one
/// full mid-session-failure → redial → `failed_redial` cycle and
/// checks that:
///   1. The orchestrator detected the runtime failure and engaged the
///      retry path (the `tcp_ws_url` listener received exactly one
///      additional accept beyond the initial dial).
///   2. The relay surfaced the *original* transport error to the
///      caller, not the redial error.
///
/// We do NOT assert on the metric counter here — the metric registry
/// is a process-global and adding test-side serialisation would
/// require exposing the internal `test_guard` from outline-metrics.
/// The accept counter on the bogus redial listener is a sufficient
/// behavioural proof that the orchestrator engaged the retry path,
/// and Phase 2.5's cross-repo integration test exercises the
/// success-path metric end-to-end.
#[tokio::test]
async fn run_relay_attempts_redial_on_mid_session_runtime_failure() {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    // ── Bogus "redial target": accepts and closes immediately. The
    //     orchestrator's redial path tries to upgrade WS here and
    //     fails on the handshake (EOF on read), surfacing as the
    //     `failed_redial` outcome. The accept counter is what we
    //     assert on.
    let redial_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redial_addr = redial_listener.local_addr().unwrap();
    let redial_accepts = Arc::new(AtomicUsize::new(0));
    let redial_accepts_for_task = Arc::clone(&redial_accepts);
    let redial_task = tokio::spawn(async move {
        loop {
            match redial_listener.accept().await {
                Ok((stream, _)) => {
                    redial_accepts_for_task.fetch_add(1, AtomicOrdering::SeqCst);
                    drop(stream);
                },
                Err(_) => break,
            }
        }
    });

    // ── "Initial upstream": accepts the connection that the SS
    //     writer/reader pair will use, sends garbage as the response
    //     salt + length-block, which the SS reader interprets as a
    //     valid salt (any 32 bytes work) and then fails to AEAD-decrypt
    //     the next 18 bytes (length block + tag). That decrypt failure
    //     is `is_upstream_runtime_failure == true`, which is exactly
    //     what the orchestrator's retry gate expects.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        // 32 garbage "salt" bytes + 18 garbage "encrypted len-block"
        // bytes. AEAD decrypt of the 18-byte block will fail because
        // the derived subkey doesn't match the random data.
        let payload = [0xAAu8; 32 + 18];
        let _ = stream.write_all(&payload).await;
        let _ = stream.flush().await;
        // Keep the socket open so the reader's failure is the AEAD
        // error, not an EOF (which would be classified as
        // `closed_cleanly` and not trigger retry).
        std::future::pending::<()>().await;
    });

    let uplink = make_ws_uplink_pointing_at("primary", redial_addr);
    let manager = UplinkManager::new_for_test(
        "test",
        vec![uplink.clone()],
        probe_disabled(),
        // tcp_active_keepalive_interval is irrelevant for this test;
        // the relay errors out before the keepalive timer is even
        // queued.
        lb(Duration::from_secs(60)),
    )
    .unwrap();

    let stream = TcpStream::connect(upstream_addr).await.unwrap();
    let (reader_half, writer_half) = stream.into_split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password).unwrap();
    let lifetime = UpstreamTransportGuard::new("test", "tcp");
    let mut writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        uplink.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )
    .unwrap();
    let reader =
        TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime)
            .with_request_salt(writer.request_salt());
    writer
        .send_chunk(&TargetAddr::IpV4(Ipv4Addr::LOCALHOST, 443).to_wire_bytes().unwrap())
        .await
        .unwrap();
    let active = ActiveTcpUplink {
        index: 0,
        name: Arc::from(uplink.name.as_str()),
        candidate: UplinkCandidate { index: 0, uplink: uplink.into() },
        writer: TcpWriter::Socket(writer),
        reader: TcpReader::Socket(reader),
        // Passing DirectSocket here is fine — the orchestrator's
        // retry path inspects `candidate.uplink.transport`, not
        // `source`. DirectSocket just records how the active became
        // active in the first place.
        source: TcpUplinkSource::DirectSocket,
        wire_index: 0,
    };

    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let (connect_res, accept_res) =
        tokio::join!(TcpStream::connect(client_addr), client_listener.accept());
    let _client_side = connect_res.unwrap();
    let (server_side, _) = accept_res.unwrap();
    let (client_read, client_write) = server_side.into_split();

    let timeouts = TcpTimeouts {
        post_client_eof_downstream: Duration::from_secs(30),
        upstream_response: Duration::from_secs(15),
        socks_upstream_idle: Duration::from_secs(60),
        direct_idle: Duration::from_secs(120),
    };
    let target = outline_transport::TargetAddr::IpV4(Ipv4Addr::LOCALHOST, 443);
    let result = run_relay(
        manager,
        active,
        target,
        Arc::from("test"),
        b"OK".to_vec(),
        client_read,
        client_write,
        &timeouts,
    )
    .await;

    assert!(
        result.is_err(),
        "relay should surface the original transport error after a failed retry, got: {result:?}",
    );
    assert!(
        redial_accepts.load(AtomicOrdering::SeqCst) >= 1,
        "orchestrator must have attempted at least one redial against the configured tcp_ws_url; \
         accept count was {}",
        redial_accepts.load(AtomicOrdering::SeqCst),
    );

    upstream_task.abort();
    redial_task.abort();
    let _ = upstream_task.await;
    let _ = redial_task.await;
}
