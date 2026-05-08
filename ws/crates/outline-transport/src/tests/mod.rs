use super::*;
use shadowsocks_crypto::CipherKind;
#[cfg(feature = "metrics")]
use crate::config::TransportMode;
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

    let ws_one = connect_websocket_with_source(&DnsCache::default(), &url, TransportMode::WsH2, None, false, "test_h2")
        .await
        .unwrap();
    let ws_two = connect_websocket_with_source(&DnsCache::default(), &url, TransportMode::WsH2, None, false, "test_h2")
        .await
        .unwrap();

    assert!(matches!(ws_one, TransportStream::H2 { .. }));
    assert!(matches!(ws_two, TransportStream::H2 { .. }));
    server.wait_for_counts(1, 2).await;
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn h2_probe_sources_do_not_reuse_shared_connections() {
    let server = TestH2Server::start().await;
    let url = server.url();

    let ws_one = connect_websocket_with_source(&DnsCache::default(), &url, TransportMode::WsH2, None, false, "probe_ws")
        .await
        .unwrap();
    let ws_two = connect_websocket_with_source(&DnsCache::default(), &url, TransportMode::WsH2, None, false, "probe_ws")
        .await
        .unwrap();

    assert!(matches!(ws_one, TransportStream::H2 { .. }));
    assert!(matches!(ws_two, TransportStream::H2 { .. }));
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
    super::ws_mode_cache::record_failure(&url, TransportMode::WsH3).await;

    let stream = connect_websocket_with_source(
        &DnsCache::default(),
        &url,
        TransportMode::WsH3,
        None,
        false,
        "test_downgrade_clamp",
    )
    .await
    .unwrap();

    assert!(matches!(stream, TransportStream::H2 { .. }));
    assert_eq!(stream.downgraded_from(), Some(TransportMode::WsH3));
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn record_success_clears_cache_when_succeeded_meets_or_exceeds_cap() {
    // Use a unique URL per test so the process-global cache map does
    // not bleed state between concurrent tests on the same host:port.
    let url = Url::parse("wss://record-success-meets.test:443/").unwrap();
    super::ws_mode_cache::record_failure(&url, TransportMode::WsH3).await;
    assert_eq!(
        super::ws_mode_cache::effective_mode(&url, TransportMode::WsH3).await,
        TransportMode::WsH2,
        "failure must clamp"
    );
    super::ws_mode_cache::record_success(&url, TransportMode::WsH3).await;
    assert_eq!(
        super::ws_mode_cache::effective_mode(&url, TransportMode::WsH3).await,
        TransportMode::WsH3,
        "successful h3 must drop the clamp so the next dial is not held back"
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn record_success_keeps_cache_when_succeeded_is_below_cap() {
    let url = Url::parse("wss://record-success-below.test:443/").unwrap();
    super::ws_mode_cache::record_failure(&url, TransportMode::WsH3).await;
    // Cap is now H2. A successful Http1 dial does not prove H2/H3 work
    // so the clamp must remain in place.
    super::ws_mode_cache::record_success(&url, TransportMode::WsH1).await;
    assert_eq!(
        super::ws_mode_cache::effective_mode(&url, TransportMode::WsH3).await,
        TransportMode::WsH2,
        "an Http1 success must not clear an H2 cap"
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn dial_at_requested_mode_carries_no_downgrade_marker() {
    let server = TestH2Server::start().await;
    let url = server.url();

    let stream = connect_websocket_with_source(
        &DnsCache::default(),
        &url,
        TransportMode::WsH2,
        None,
        false,
        "test_no_downgrade",
    )
    .await
    .unwrap();

    assert!(matches!(stream, TransportStream::H2 { .. }));
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
    super::ws_mode_cache::record_failure(&url, TransportMode::WsH3).await;

    let counter = Arc::new(AtomicUsize::new(0));
    let observed_mode = Arc::new(parking_lot::Mutex::new(None::<TransportMode>));
    let counter_for_hook = Arc::clone(&counter);
    let observed_for_hook = Arc::clone(&observed_mode);
    let hook: VlessUdpDowngradeNotifier = Arc::new(move |requested: TransportMode| {
        counter_for_hook.fetch_add(1, Ordering::SeqCst);
        *observed_for_hook.lock() = Some(requested);
    });

    let mux = VlessUdpSessionMux::new(
        Arc::new(DnsCache::default()),
        url,
        TransportMode::WsH3,
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
        Some(TransportMode::WsH3),
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
    super::ws_mode_cache::record_failure(&url, TransportMode::WsH3).await;

    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_hook = Arc::clone(&counter);
    let hook: VlessUdpDowngradeNotifier = Arc::new(move |_requested: TransportMode| {
        counter_for_hook.fetch_add(1, Ordering::SeqCst);
    });

    let mux = VlessUdpSessionMux::new(
        Arc::new(DnsCache::default()),
        url,
        TransportMode::WsH3,
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

// ── Ack-Prefix Protocol v1 capability negotiation ─────────────────────────────
//
// These tests cover the request-side advertise + response-side echo glue
// for `connect_websocket_with_resume`. The wire-format parser itself is
// tested in `tests/ack_prefix.rs`; here we verify that:
//   1. Advertise + echo → `ack_prefix_advertised_by_server() == true`.
//   2. No advertise → flag stays `false`, regardless of server behaviour.
//   3. Advertise but server stays silent → flag stays `false`.
//
// We use a parallel H2 mock instead of extending `TestH2Server` so the
// existing tests' assertions about request shape stay verbatim.

#[cfg(feature = "metrics")]
struct TestH2AckPrefixServer {
    addr: std::net::SocketAddr,
    last_request_advertised: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "metrics")]
impl TestH2AckPrefixServer {
    /// Spawns a server that, on each CONNECT, records whether the request
    /// carried `X-Outline-Resume-Ack-Prefix: 1` and — if `echo_back` —
    /// echoes the same header on the response. The recorded bit lets a
    /// test assert that the *client* actually sent the advertise header
    /// even when no echo comes back.
    async fn start(echo_back: bool) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let last_request_advertised = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recorder = Arc::clone(&last_request_advertised);

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(values) => values,
                    Err(_) => break,
                };
                let recorder = Arc::clone(&recorder);
                tokio::spawn(async move {
                    let _ = serve_h2_ack_prefix_connection(stream, recorder, echo_back).await;
                });
            }
        });

        Self { addr, last_request_advertised }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("ws://{}/ack-prefix-h2", self.addr)).unwrap()
    }

    fn last_request_advertised(&self) -> bool {
        self.last_request_advertised.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "metrics")]
async fn serve_h2_ack_prefix_connection(
    stream: TcpStream,
    last_request_advertised: Arc<std::sync::atomic::AtomicBool>,
    echo_back: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = hyper_http2::Builder::new(TokioExecutor::new());
    builder.enable_connect_protocol();
    builder
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req: Request<Incoming>| {
                let recorder = Arc::clone(&last_request_advertised);
                async move {
                    let advertised = req
                        .headers()
                        .get(crate::resumption::ACK_PREFIX_HEADER)
                        .and_then(|v| v.to_str().ok())
                        == Some("1");
                    recorder.store(advertised, Ordering::SeqCst);

                    let on_upgrade = hyper::upgrade::on(req);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = on_upgrade.await {
                            let _upgraded = upgraded;
                            std::future::pending::<()>().await;
                        }
                    });

                    let mut response = Response::new(Empty::<Bytes>::new());
                    if echo_back && advertised {
                        response.headers_mut().insert(
                            crate::resumption::ACK_PREFIX_HEADER,
                            http::HeaderValue::from_static("1"),
                        );
                    }
                    Ok::<_, hyper::Error>(response)
                }
            }),
        )
        .await?;
    Ok(())
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn ack_prefix_negotiation_succeeds_when_both_peers_set_header() {
    let server = TestH2AckPrefixServer::start(true).await;
    let url = server.url();

    let stream = connect_websocket_with_resume(
        &DnsCache::default(),
        &url,
        TransportMode::WsH2,
        None,
        false,
        "test_ack_prefix_pos",
        None,
        true,
        // Existing v1 negotiation tests don't exercise v2.
        false,
    )
    .await
    .unwrap();

    assert!(matches!(stream, TransportStream::H2 { .. }));
    assert!(
        server.last_request_advertised(),
        "client must send X-Outline-Resume-Ack-Prefix when ack_prefix_requested = true",
    );
    assert!(
        stream.ack_prefix_advertised_by_server(),
        "server echoed the capability — accessor must return true",
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn ack_prefix_flag_stays_false_when_client_does_not_advertise() {
    // Even with an echoing server, a client that does not advertise must
    // never see the flag set — gates the receiver against accidental
    // 14-byte parse on a stream where the first chunk is real data.
    let server = TestH2AckPrefixServer::start(true).await;
    let url = server.url();

    let stream = connect_websocket_with_resume(
        &DnsCache::default(),
        &url,
        TransportMode::WsH2,
        None,
        false,
        "test_ack_prefix_no_advertise",
        None,
        false,
        // v1 off → v2 also off (gated on v1).
        false,
    )
    .await
    .unwrap();

    assert!(matches!(stream, TransportStream::H2 { .. }));
    assert!(
        !server.last_request_advertised(),
        "client must NOT send the header when ack_prefix_requested = false",
    );
    assert!(
        !stream.ack_prefix_advertised_by_server(),
        "client did not advertise — accessor must stay false",
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn ack_prefix_flag_stays_false_when_server_does_not_echo() {
    // Old/disabled servers omit the response header even when the client
    // advertises. The negotiation must collapse to "off" so the receiver
    // does not look for a control frame in the byte stream.
    let server = TestH2AckPrefixServer::start(false).await;
    let url = server.url();

    let stream = connect_websocket_with_resume(
        &DnsCache::default(),
        &url,
        TransportMode::WsH2,
        None,
        false,
        "test_ack_prefix_silent_server",
        None,
        true,
        // Existing v1-silence test doesn't exercise v2.
        false,
    )
    .await
    .unwrap();

    assert!(matches!(stream, TransportStream::H2 { .. }));
    assert!(
        server.last_request_advertised(),
        "client still sends the request-side header when ack_prefix_requested = true",
    );
    assert!(
        !stream.ack_prefix_advertised_by_server(),
        "server stayed silent — accessor must stay false",
    );
}

// ── Symmetric Downlink Replay v2 capability negotiation ───────────────────────
//
// Mirror of the v1 H2-mock harness, extended to record/echo BOTH headers
// so the v2-on-v1 gating can be exercised end-to-end. The four tests
// below cover: positive happy path, client-no-advertise, server-silent,
// and the v2-without-v1 gate (server MUST NOT echo v2 if the client
// did not also advertise v1).

#[cfg(feature = "metrics")]
struct TestH2SymmetricReplayServer {
    addr: std::net::SocketAddr,
    last_request_v1_advertised: Arc<std::sync::atomic::AtomicBool>,
    last_request_v2_advertised: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "metrics")]
impl TestH2SymmetricReplayServer {
    /// Spawns a server that records whether each capability header was
    /// present on the request. `echo_v1`/`echo_v2` toggle the per-side
    /// echo independently so the gating tests can simulate buggy or
    /// half-implemented servers.
    async fn start(echo_v1: bool, echo_v2: bool) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let last_request_v1_advertised = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let last_request_v2_advertised = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recorder_v1 = Arc::clone(&last_request_v1_advertised);
        let recorder_v2 = Arc::clone(&last_request_v2_advertised);

        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(values) => values,
                    Err(_) => break,
                };
                let recorder_v1 = Arc::clone(&recorder_v1);
                let recorder_v2 = Arc::clone(&recorder_v2);
                tokio::spawn(async move {
                    let _ = serve_h2_symmetric_replay_connection(
                        stream,
                        recorder_v1,
                        recorder_v2,
                        echo_v1,
                        echo_v2,
                    )
                    .await;
                });
            }
        });

        Self {
            addr,
            last_request_v1_advertised,
            last_request_v2_advertised,
        }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("ws://{}/symmetric-replay-h2", self.addr)).unwrap()
    }

    fn last_request_v1_advertised(&self) -> bool {
        self.last_request_v1_advertised.load(Ordering::SeqCst)
    }

    fn last_request_v2_advertised(&self) -> bool {
        self.last_request_v2_advertised.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "metrics")]
async fn serve_h2_symmetric_replay_connection(
    stream: TcpStream,
    recorder_v1: Arc<std::sync::atomic::AtomicBool>,
    recorder_v2: Arc<std::sync::atomic::AtomicBool>,
    echo_v1: bool,
    echo_v2: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = hyper_http2::Builder::new(TokioExecutor::new());
    builder.enable_connect_protocol();
    builder
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req: Request<Incoming>| {
                let recorder_v1 = Arc::clone(&recorder_v1);
                let recorder_v2 = Arc::clone(&recorder_v2);
                async move {
                    let v1_advertised = req
                        .headers()
                        .get(crate::resumption::ACK_PREFIX_HEADER)
                        .and_then(|v| v.to_str().ok())
                        == Some("1");
                    let v2_advertised = req
                        .headers()
                        .get(crate::resumption::SYMMETRIC_REPLAY_HEADER)
                        .and_then(|v| v.to_str().ok())
                        == Some("1");
                    recorder_v1.store(v1_advertised, Ordering::SeqCst);
                    recorder_v2.store(v2_advertised, Ordering::SeqCst);

                    let on_upgrade = hyper::upgrade::on(req);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = on_upgrade.await {
                            let _upgraded = upgraded;
                            std::future::pending::<()>().await;
                        }
                    });

                    let mut response = Response::new(Empty::<Bytes>::new());
                    if echo_v1 && v1_advertised {
                        response.headers_mut().insert(
                            crate::resumption::ACK_PREFIX_HEADER,
                            http::HeaderValue::from_static("1"),
                        );
                    }
                    if echo_v2 && v2_advertised {
                        response.headers_mut().insert(
                            crate::resumption::SYMMETRIC_REPLAY_HEADER,
                            http::HeaderValue::from_static("1"),
                        );
                    }
                    Ok::<_, hyper::Error>(response)
                }
            }),
        )
        .await?;
    Ok(())
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn symmetric_replay_negotiation_succeeds_when_both_peers_set_both_headers() {
    let server = TestH2SymmetricReplayServer::start(true, true).await;
    let url = server.url();

    let stream = connect_websocket_with_resume(
        &DnsCache::default(),
        &url,
        TransportMode::WsH2,
        None,
        false,
        "test_symmetric_replay_pos",
        None,
        true,
        true,
    )
    .await
    .unwrap();

    assert!(matches!(stream, TransportStream::H2 { .. }));
    assert!(
        server.last_request_v1_advertised(),
        "client must send v1 header when ack_prefix_requested = true",
    );
    assert!(
        server.last_request_v2_advertised(),
        "client must send v2 header when symmetric_replay_requested = true",
    );
    assert!(
        stream.ack_prefix_advertised_by_server(),
        "server echoed v1 — accessor must return true",
    );
    assert!(
        stream.symmetric_replay_advertised_by_server(),
        "server echoed v2 — accessor must return true",
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn symmetric_replay_flag_stays_false_when_client_does_not_advertise_v2() {
    // Client opts into v1 only. v2 echo must stay off because the
    // request never carried `X-Outline-Resume-Symmetric-Replay`.
    let server = TestH2SymmetricReplayServer::start(true, true).await;
    let url = server.url();

    let stream = connect_websocket_with_resume(
        &DnsCache::default(),
        &url,
        TransportMode::WsH2,
        None,
        false,
        "test_symmetric_replay_no_v2_advertise",
        None,
        true,
        false,
    )
    .await
    .unwrap();

    assert!(
        server.last_request_v1_advertised(),
        "v1 still advertised independently",
    );
    assert!(
        !server.last_request_v2_advertised(),
        "client must NOT send v2 header when symmetric_replay_requested = false",
    );
    assert!(
        stream.ack_prefix_advertised_by_server(),
        "v1 negotiation still succeeds in this scenario",
    );
    assert!(
        !stream.symmetric_replay_advertised_by_server(),
        "client did not advertise v2 — accessor must stay false",
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn symmetric_replay_flag_stays_false_when_server_silent_on_v2_only() {
    // Server echoes v1 but suppresses v2 — old or partially-rolled-out
    // server. v1 must light up; v2 must stay off.
    let server = TestH2SymmetricReplayServer::start(true, false).await;
    let url = server.url();

    let stream = connect_websocket_with_resume(
        &DnsCache::default(),
        &url,
        TransportMode::WsH2,
        None,
        false,
        "test_symmetric_replay_silent_v2_server",
        None,
        true,
        true,
    )
    .await
    .unwrap();

    assert!(
        server.last_request_v1_advertised() && server.last_request_v2_advertised(),
        "client advertises both even when server is partially-implemented",
    );
    assert!(
        stream.ack_prefix_advertised_by_server(),
        "v1 echo present — accessor must reflect it",
    );
    assert!(
        !stream.symmetric_replay_advertised_by_server(),
        "server stayed silent on v2 — accessor must stay false",
    );
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn symmetric_replay_flag_stays_false_when_v1_negotiation_collapsed() {
    // Server echoes neither header → v1 collapses to off, and per spec
    // v2 cannot exist without v1. Local gate inside the dialer enforces
    // this even if the server were to echo v2 alone.
    let server = TestH2SymmetricReplayServer::start(false, false).await;
    let url = server.url();

    let stream = connect_websocket_with_resume(
        &DnsCache::default(),
        &url,
        TransportMode::WsH2,
        None,
        false,
        "test_symmetric_replay_v1_collapsed",
        None,
        true,
        true,
    )
    .await
    .unwrap();

    assert!(
        !stream.ack_prefix_advertised_by_server(),
        "server suppressed v1 echo — accessor must be false",
    );
    assert!(
        !stream.symmetric_replay_advertised_by_server(),
        "v1 collapsed → v2 must collapse too (gated on v1)",
    );
}
