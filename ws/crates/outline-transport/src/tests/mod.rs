use super::*;
use shadowsocks_crypto::CipherKind;
#[cfg(feature = "metrics")]
use crate::config::WsTransportMode;
#[cfg(feature = "metrics")]
use bytes::Bytes;
#[cfg(feature = "metrics")]
use http::{Method, Request, Response, Version};
#[cfg(feature = "metrics")]
use http_body_util::Empty;
use std::sync::Arc;
#[cfg(feature = "metrics")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "metrics")]
use std::time::Duration;
use tokio::io::AsyncReadExt;
#[cfg(feature = "metrics")]
use tokio::net::TcpStream;
use tokio::net::{TcpListener, UdpSocket};
#[cfg(feature = "metrics")]
use url::Url;

#[cfg(feature = "metrics")]
use hyper::body::Incoming;
#[cfg(feature = "metrics")]
use hyper::ext::Protocol;
#[cfg(feature = "metrics")]
use hyper::server::conn::http2 as hyper_http2;
#[cfg(feature = "metrics")]
use hyper::service::service_fn;
#[cfg(feature = "metrics")]
use hyper_util::rt::{TokioExecutor, TokioIo};

#[tokio::test]
async fn tcp_writer_splits_large_aead_payload_into_multiple_chunks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 128 * 1024];
        let mut total = 0usize;
        loop {
            let read = stream.read(&mut buf[total..]).await.unwrap();
            if read == 0 {
                break;
            }
            total += read;
        }
        total
    });

    let stream = TcpStream::connect(addr).await.unwrap();
    let (_reader_half, writer_half) = stream.into_split();
    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher.derive_master_key("password").unwrap();
    let lifetime = UpstreamTransportGuard::new("test", "tcp");
    let mut writer =
        TcpShadowsocksWriter::connect_socket(writer_half, cipher, &master_key, lifetime).unwrap();
    let payload = vec![0x42; 40_000];

    writer.send_chunk(&payload).await.unwrap();
    writer.close().await.unwrap();

    let total = server.await.unwrap();
    assert!(total > payload.len());
}

#[tokio::test]
async fn udp_socket_transport_close_wakes_blocked_reader() {
    let transport = Arc::new(
        UdpWsTransport::from_socket(
            UdpSocket::bind(("127.0.0.1", 0)).await.unwrap(),
            CipherKind::Chacha20IetfPoly1305,
            "password",
            "test",
        )
        .unwrap(),
    );
    let reader_transport = Arc::clone(&transport);
    let read_task = tokio::spawn(async move { reader_transport.read_packet().await });

    transport.close().await.unwrap();

    let error = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        read_task.await.unwrap().unwrap_err()
    })
    .await
    .unwrap();
    assert!(format!("{error:#}").contains("udp transport closed"));
}

#[tokio::test]
async fn connect_tcp_socket_enables_nodelay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });

    let stream = connect_tcp_socket(addr, None).await.unwrap();
    assert!(stream.nodelay().unwrap());

    drop(stream);
    server.await.unwrap();
}

#[cfg(feature = "metrics")]
struct TestH2Server {
    addr: std::net::SocketAddr,
    accepted_connections: Arc<AtomicUsize>,
    connect_requests: Arc<AtomicUsize>,
}

#[cfg(feature = "metrics")]
impl TestH2Server {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let connect_requests = Arc::new(AtomicUsize::new(0));
        let accepted_task = Arc::clone(&accepted_connections);
        let requests_task = Arc::clone(&connect_requests);

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(values) => values,
                    Err(_) => break,
                };
                accepted_task.fetch_add(1, Ordering::SeqCst);
                let requests = Arc::clone(&requests_task);
                tokio::spawn(async move {
                    let _ = serve_h2_websocket_connection(stream, requests).await;
                });
            }
        });

        Self {
            addr,
            accepted_connections,
            connect_requests,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("ws://{}/shared-h2", self.addr)).unwrap()
    }

    async fn wait_for_counts(&self, expected_connections: usize, expected_requests: usize) {
        for _ in 0..40 {
            if self.accepted_connections.load(Ordering::SeqCst) == expected_connections
                && self.connect_requests.load(Ordering::SeqCst) == expected_requests
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        panic!(
            "unexpected h2 server counts: connections={}, requests={}",
            self.accepted_connections.load(Ordering::SeqCst),
            self.connect_requests.load(Ordering::SeqCst),
        );
    }
}

#[cfg(feature = "metrics")]
async fn serve_h2_websocket_connection(
    stream: TcpStream,
    connect_requests: Arc<AtomicUsize>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = hyper_http2::Builder::new(TokioExecutor::new());
    builder.enable_connect_protocol();
    builder
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req: Request<Incoming>| {
                let requests = Arc::clone(&connect_requests);
                async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(req.method(), Method::CONNECT);
                    assert_eq!(req.version(), Version::HTTP_2);
                    assert_eq!(
                        req.extensions().get::<Protocol>(),
                        Some(&Protocol::from_static("websocket"))
                    );
                    assert_eq!(
                        req.headers().get(http::header::SEC_WEBSOCKET_VERSION),
                        Some(&http::HeaderValue::from_static("13"))
                    );

                    let on_upgrade = hyper::upgrade::on(req);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = on_upgrade.await {
                            let _upgraded = upgraded;
                            std::future::pending::<()>().await;
                        }
                    });

                    Ok::<_, hyper::Error>(Response::new(Empty::<Bytes>::new()))
                }
            }),
        )
        .await?;
    Ok(())
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn h2_reuses_shared_connection_for_non_probe_sources() {
    let server = TestH2Server::start().await;
    let url = server.url();

    let ws_one = connect_websocket_with_source(&DnsCache::default(), &url, WsTransportMode::H2, None, false, "test_h2")
        .await
        .unwrap();
    let ws_two = connect_websocket_with_source(&DnsCache::default(), &url, WsTransportMode::H2, None, false, "test_h2")
        .await
        .unwrap();

    assert!(matches!(ws_one, WsTransportStream::H2 { .. }));
    assert!(matches!(ws_two, WsTransportStream::H2 { .. }));
    server.wait_for_counts(1, 2).await;
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn h2_probe_sources_do_not_reuse_shared_connections() {
    let server = TestH2Server::start().await;
    let url = server.url();

    let ws_one = connect_websocket_with_source(&DnsCache::default(), &url, WsTransportMode::H2, None, false, "probe_ws")
        .await
        .unwrap();
    let ws_two = connect_websocket_with_source(&DnsCache::default(), &url, WsTransportMode::H2, None, false, "probe_ws")
        .await
        .unwrap();

    assert!(matches!(ws_one, WsTransportStream::H2 { .. }));
    assert!(matches!(ws_two, WsTransportStream::H2 { .. }));
    server.wait_for_counts(2, 2).await;
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn ws_mode_cache_clamp_marks_stream_as_downgraded_from_requested() {
    // Pre-populating the per-host `ws_mode_cache` with an H3 failure forces
    // `effective_mode` to clamp the next H3 dial down to H2 before any
    // handshake. The returned stream should carry `downgraded_from = Some(H3)`
    // so uplink-manager callsites can mirror the downgrade into their
    // per-uplink window.
    let server = TestH2Server::start().await;
    let url = server.url();
    super::ws_mode_cache::record_failure(&url, WsTransportMode::H3).await;

    let stream = connect_websocket_with_source(
        &DnsCache::default(),
        &url,
        WsTransportMode::H3,
        None,
        false,
        "test_downgrade_clamp",
    )
    .await
    .unwrap();

    assert!(matches!(stream, WsTransportStream::H2 { .. }));
    assert_eq!(stream.downgraded_from(), Some(WsTransportMode::H3));
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn dial_at_requested_mode_carries_no_downgrade_marker() {
    let server = TestH2Server::start().await;
    let url = server.url();

    let stream = connect_websocket_with_source(
        &DnsCache::default(),
        &url,
        WsTransportMode::H2,
        None,
        false,
        "test_no_downgrade",
    )
    .await
    .unwrap();

    assert!(matches!(stream, WsTransportStream::H2 { .. }));
    assert_eq!(stream.downgraded_from(), None);
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn vless_udp_mux_invokes_on_downgrade_hook_after_clamp_and_latches() {
    use crate::vless::{VlessUdpDowngradeNotifier, VlessUdpSessionMux};
    use socks5_proto::TargetAddr;
    use std::net::Ipv4Addr;

    // Pre-populate the per-host clamp so any H3 dial against this URL is
    // silently routed to H2 inside `connect_websocket_with_resume`. The mux
    // should observe `downgraded_from = Some(H3)` on its first per-target
    // dial and fire the hook exactly once.
    let server = TestH2Server::start().await;
    let url = server.url();
    super::ws_mode_cache::record_failure(&url, WsTransportMode::H3).await;

    let counter = Arc::new(AtomicUsize::new(0));
    let observed_mode = Arc::new(parking_lot::Mutex::new(None::<WsTransportMode>));
    let counter_for_hook = Arc::clone(&counter);
    let observed_for_hook = Arc::clone(&observed_mode);
    let hook: VlessUdpDowngradeNotifier = Arc::new(move |requested: WsTransportMode| {
        counter_for_hook.fetch_add(1, Ordering::SeqCst);
        *observed_for_hook.lock() = Some(requested);
    });

    let mux = VlessUdpSessionMux::new(
        Arc::new(DnsCache::default()),
        url,
        WsTransportMode::H3,
        [0u8; 16],
        None,
        false,
        "test_vless_downgrade",
        None,
    )
    .with_on_downgrade(Some(hook));

    let target1 = TargetAddr::IpV4(Ipv4Addr::new(127, 0, 0, 1), 9999);
    let _ = mux.session_for(&target1).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "hook must fire once on the first downgraded dial"
    );
    assert_eq!(
        *observed_mode.lock(),
        Some(WsTransportMode::H3),
        "hook must receive the originally-requested mode, not the dialed one"
    );

    // Latch: a second per-target dial during the same outage window must
    // not refire the hook (otherwise we'd spam the uplink-manager every
    // time a UDP burst opens fresh sessions).
    let target2 = TargetAddr::IpV4(Ipv4Addr::new(127, 0, 0, 1), 9998);
    let _ = mux.session_for(&target2).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "hook must latch — only fire once per mux instance"
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn vless_udp_mux_resets_downgrade_latch_after_recovery_dial() {
    use crate::vless::{VlessUdpDowngradeNotifier, VlessUdpSessionMux};
    use socks5_proto::TargetAddr;
    use std::net::Ipv4Addr;

    // First downgrade — hook fires, latch flips to true.
    let server = TestH2Server::start().await;
    let url = server.url();
    super::ws_mode_cache::record_failure(&url, WsTransportMode::H3).await;

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_hook = Arc::clone(&counter);
    let hook: VlessUdpDowngradeNotifier = Arc::new(move |_requested: WsTransportMode| {
        counter_for_hook.fetch_add(1, Ordering::SeqCst);
    });

    let mux = VlessUdpSessionMux::new(
        Arc::new(DnsCache::default()),
        url,
        WsTransportMode::H3,
        [0u8; 16],
        None,
        false,
        "test_vless_recovery",
        None,
    )
    .with_on_downgrade(Some(hook));

    let target1 = TargetAddr::IpV4(Ipv4Addr::new(127, 0, 0, 1), 9999);
    let _ = mux.session_for(&target1).await;
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert!(mux.downgrade_latch_for_test());

    // Recovery: simulate `downgraded_from = None` by resetting the latch.
    // The Mux runs this branch automatically whenever a per-target dial
    // succeeds at the requested mode (real H3 came back); we drive it via
    // the test-only helper because there's no public API to clear an
    // entry from `ws_mode_cache` on demand.
    mux.force_reset_downgrade_latch_for_test();
    assert!(!mux.downgrade_latch_for_test());

    // A subsequent downgrade during the *same* mux instance must refire
    // the hook now that the latch has been cleared.
    let target2 = TargetAddr::IpV4(Ipv4Addr::new(127, 0, 0, 1), 9998);
    let _ = mux.session_for(&target2).await;
    assert_eq!(
        counter.load(Ordering::SeqCst),
        2,
        "after the recovery branch resets the latch, a fresh downgrade must fire the hook again"
    );
    assert!(mux.downgrade_latch_for_test());
}
