use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use outline_ws_rust::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig, WsProbeConfig};
use outline_ws_rust::types::{CipherKind, UplinkTransport, WsTransportMode};
use outline_ws_rust::uplink::UplinkManager;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
#[cfg(feature = "env-filter")]
use tracing_subscriber::EnvFilter;
use url::Url;

#[tokio::test]
async fn tcp_standby_validation_replaces_closed_idle_connection() {
    init_test_tracing();
    let server = TestWsServer::start().await;
    let manager = build_manager(server.url(), None, 1, 0).await;

    manager.run_standby_maintenance().await;
    wait_for_standby(&manager, 1, 0, &server).await;
    assert_eq!(server.accepted_connections(), 1);

    server.close_all().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    manager.run_standby_maintenance().await;
    wait_for_standby(&manager, 1, 0, &server).await;
    assert!(
        server.accepted_connections() >= 2,
        "expected standby validation to reconnect after idle close"
    );
}

#[tokio::test]
async fn udp_standby_validation_replaces_closed_idle_connection() {
    init_test_tracing();
    let server = TestWsServer::start().await;
    let manager = build_manager(server.url(), Some(server.url()), 0, 1).await;

    manager.run_standby_maintenance().await;
    wait_for_standby(&manager, 0, 1, &server).await;
    assert_eq!(server.accepted_connections(), 1);

    server.close_all().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    manager.run_standby_maintenance().await;
    wait_for_standby(&manager, 0, 1, &server).await;
    assert!(
        server.accepted_connections() >= 2,
        "expected standby validation to reconnect after idle close"
    );
}

async fn build_manager(
    tcp_ws_url: Url,
    udp_ws_url: Option<Url>,
    warm_standby_tcp: usize,
    warm_standby_udp: usize,
) -> UplinkManager {
    UplinkManager::new(
        "test",
        vec![UplinkConfig {
            name: "test".to_string(),
            transport: UplinkTransport::Websocket,
            tcp_ws_url: Some(tcp_ws_url),
            tcp_ws_mode: WsTransportMode::Http1,
            udp_ws_url,
            udp_ws_mode: WsTransportMode::Http1,
            tcp_addr: None,
            udp_addr: None,
            cipher: CipherKind::Chacha20IetfPoly1305,
            password: "Secret0".to_string(),
            weight: 1.0,
            fwmark: None,
            ipv6_first: false,
        }],
        ProbeConfig {
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_concurrent: 2,
            max_dials: 1,
            min_failures: 1,
            attempts: 1,
            ws: WsProbeConfig { enabled: false },
            http: None,
            dns: None,
            tcp: None,
        },
        LoadBalancingConfig {
            mode: outline_ws_rust::config::LoadBalancingMode::ActiveActive,
            routing_scope: outline_ws_rust::config::RoutingScope::PerFlow,
            sticky_ttl: Duration::from_secs(300),
            hysteresis: Duration::from_millis(50),
            failure_cooldown: Duration::from_secs(10),
            tcp_chunk0_failover_timeout: Duration::from_secs(10),
            warm_standby_tcp,
            warm_standby_udp,
            rtt_ewma_alpha: 0.3,
            failure_penalty: Duration::from_millis(500),
            failure_penalty_max: Duration::from_secs(30),
            failure_penalty_halflife: Duration::from_secs(60),
            h3_downgrade_duration: Duration::from_secs(60),
            udp_ws_keepalive_interval: None,
            tcp_ws_standby_keepalive_interval: None,
            tcp_active_keepalive_interval: None,
            auto_failback: false,
        },
        std::sync::Arc::new(outline_transport::DnsCache::default()),
    )
    .expect("manager must build")
}

async fn wait_for_standby(
    manager: &UplinkManager,
    tcp_ready: usize,
    udp_ready: usize,
    server: &TestWsServer,
) {
    for _ in 0..20 {
        manager.run_standby_maintenance().await;
        let snapshot = manager.snapshot().await;
        let uplink = &snapshot.uplinks[0];
        if uplink.standby_tcp_ready == tcp_ready && uplink.standby_udp_ready == udp_ready {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let snapshot = manager.snapshot().await;
    panic!(
        "unexpected standby state: tcp={}, udp={}, accepted_connections={}",
        snapshot.uplinks[0].standby_tcp_ready,
        snapshot.uplinks[0].standby_udp_ready,
        server.accepted_connections(),
    );
}

fn init_test_tracing() {
    #[cfg(feature = "env-filter")]
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("debug,outline_ws_rust=debug"))
        .with_test_writer()
        .try_init();

    #[cfg(not(feature = "env-filter"))]
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
}

struct TestWsServer {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    connections: Arc<Mutex<Vec<mpsc::UnboundedSender<()>>>>,
}

impl TestWsServer {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind ws server");
        let addr = listener.local_addr().expect("ws server addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(Mutex::new(Vec::new()));

        let accepted_task = Arc::clone(&accepted);
        let connections_task = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                accepted_task.fetch_add(1, Ordering::SeqCst);
                let connections = Arc::clone(&connections_task);
                tokio::spawn(async move {
                    let _ = handle_ws_connection(stream, connections).await;
                });
            }
        });

        Self { addr, accepted, connections }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("ws://{}/standby", self.addr)).expect("valid ws url")
    }

    fn accepted_connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    async fn close_all(&self) {
        let senders = self.connections.lock().await.clone();
        for sender in senders {
            let _ = sender.send(());
        }
    }
}

async fn handle_ws_connection(
    stream: TcpStream,
    connections: Arc<Mutex<Vec<mpsc::UnboundedSender<()>>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut ws = accept_async(stream).await?;
    let (close_tx, mut close_rx) = mpsc::unbounded_channel();
    connections.lock().await.push(close_tx);

    loop {
        tokio::select! {
            maybe_message = ws.next() => {
                let Some(message) = maybe_message else {
                    break;
                };
                match message? {
                    Message::Ping(payload) => ws.send(Message::Pong(payload)).await?,
                    Message::Close(_) => break,
                    Message::Text(_) | Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
                }
            }
            close = close_rx.recv() => {
                if close.is_some() {
                    ws.close(None).await?;
                }
                break;
            }
        }
    }

    Ok(())
}
