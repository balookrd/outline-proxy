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
        udp_ws_keepalive_interval: None,
        tcp_ws_keepalive_interval: None,
        tcp_ws_standby_keepalive_interval: None,
        tcp_active_keepalive_interval: Some(keepalive_interval),
        auto_failback: false,
        vless_udp_mux_limits: VlessUdpMuxLimits::default(),
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
    let relay_task = tokio::spawn(async move {
        run_relay(
            manager,
            active,
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
