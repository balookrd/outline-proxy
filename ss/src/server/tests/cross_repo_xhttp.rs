//! Cross-repo end-to-end XHTTP integration tests.
//!
//! Drives the real `outline-ws-rust` client crate (sibling repo,
//! pulled in as a dev-dep with a relative-path entry) against the
//! real `outline-ss-rust` server in a single tokio process. A
//! local TCP echo upstream stands in for the VLESS target, and the
//! client's `connect_websocket_with_resume` is the public entry —
//! the same one production callers use.
//!
//! Two carrier classes are covered:
//!   * **h2 over plain TCP** (`http://` URL): the client picks
//!     `BoxedIo::Plain` whenever the scheme is not `https`/`wss`,
//!     and axum accepts h2 prior-knowledge over plain TCP. No TLS
//!     plumbing needed.
//!   * **h3 over TLS+QUIC** (`https://` URL): h3 is TLS-only on
//!     both sides. Tests share a self-signed cert via a
//!     process-cached helper and install the matching root on the
//!     client through `outline_transport::install_test_tls_root`,
//!     so the dial trusts the in-process server.
//!
//! What these tests cover that single-side mocks do not: header
//! capitalisation, edge-case parser behaviour, end-to-end framing,
//! TLS / QUIC handshake compatibility. Disagreements between the
//! server's axum / h3 routes and the client's hyper / quinn
//! builders surface here.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, WebSocketServer as H3WebSocketServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

use outline_transport::{
    DnsCache as ClientDnsCache, TransportMode, TransportStream, connect_websocket_with_resume,
};

use super::super::nat::NatTable;
use super::super::resumption;
use super::super::setup::{VlessXhttpUserRoute, build_xhttp_vless_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, Services, UdpServices, UserKeySlice};
use super::super::transport::XhttpRegistry;
use super::super::{DnsCache, serve_h3_server};
use super::sample_config;
use super::xhttp::{
    TEST_UUID, build_vless_tcp_handshake, setup_xhttp_server,
    setup_xhttp_server_with_resumption,
};
use crate::config::H3Alpn;
use crate::crypto::UserKey;
use crate::metrics::Metrics;
use crate::protocol::vless::{VERSION, VlessUser};

/// Drains binary frames from the client stream until the
/// accumulated payload reaches `expected` bytes (or the stream
/// ends). The server-side relay frequently splits the VLESS
/// response header and the first downlink payload into two
/// separate `push_downlink` calls, which surface as two
/// `Message::Binary` frames on the client.
async fn read_binary_until_at_least(
    stream: &mut TransportStream,
    expected: usize,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    while buf.len() < expected {
        match stream.next().await {
            Some(Ok(Message::Binary(bytes))) => buf.extend_from_slice(&bytes),
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(other)) => bail!("unexpected message variant: {other:?}"),
            Some(Err(e)) => bail!("stream error: {e}"),
        }
    }
    Ok(buf)
}

#[tokio::test]
async fn cross_repo_xhttp_packet_up_h2_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;

    // The client picks TLS off `url.scheme()`; `http://` keeps the
    // dial on plain TCP h2, exercising the same `BoxedIo::Plain`
    // branch that the client's own mock test uses.
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("http://{listen_addr}/xh"))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-test",
        None,
    )
    .await?;

    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    stream.send(Message::Binary(Bytes::from(handshake))).await?;

    let received = read_binary_until_at_least(&mut stream, 6).await?;
    assert_eq!(&received[..2], &[VERSION, 0x00], "vless response header");
    assert_eq!(&received[2..6], b"pong", "echoed payload");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(stream);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn cross_repo_xhttp_stream_one_h2_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_server("/xh").await?;

    // Stream-one is selected entirely by `?mode=stream-one` on the
    // dial URL — no second config knob, both sides parse the query.
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("http://{listen_addr}/xh?mode=stream-one"))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-test",
        None,
    )
    .await?;

    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    stream.send(Message::Binary(Bytes::from(handshake))).await?;

    let received = read_binary_until_at_least(&mut stream, 6).await?;
    assert_eq!(&received[..2], &[VERSION, 0x00]);
    assert_eq!(&received[2..6], b"pong");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(stream);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn cross_repo_xhttp_h2_resume_reattaches_parked_upstream() -> Result<()> {
    // Echo upstream that handles two read/reply rounds on one
    // accepted socket. Resume preserves the upstream across the
    // client A → client B switch; if it didn't, the second client's
    // `read_exact` would never fire (the upstream task only
    // accepts once, and a fresh dial would open a new TCP socket).
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut first = [0_u8; 4];
        stream.read_exact(&mut first).await?;
        stream.write_all(b"pong").await?;
        let mut second = [0_u8; 4];
        stream.read_exact(&mut second).await?;
        stream.write_all(b"ackk").await?;
        Result::<_, anyhow::Error>::Ok((first, second))
    });

    let (listen_addr, server, registry) = setup_xhttp_server_with_resumption("/xh", true).await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("http://{listen_addr}/xh"))?;

    // ── Client A: capability advertise + first round-trip ──────
    let mut stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-resume-a",
        None,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;

    let handshake_a = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    stream_a.send(Message::Binary(Bytes::from(handshake_a))).await?;
    let received_a = read_binary_until_at_least(&mut stream_a, 6).await?;
    assert_eq!(&received_a[..2], &[VERSION, 0x00]);
    assert_eq!(&received_a[2..6], b"pong");

    // The client crate has no FIN signal yet, so we drive a
    // graceful uplink-EOF straight on the session: the relay sees
    // EOF, exits, and the cleanup path parks the live upstream
    // into the orphan registry under `token`.
    let session = registry
        .first_session()
        .ok_or_else(|| anyhow::anyhow!("session A missing from registry"))?;
    session.close_uplink();
    // The relay needs a moment to wake from its uplink-park,
    // observe EOF, and shove the upstream into the orphan
    // registry. Without this sleep client B's resume can race
    // the park and miss it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(stream_a);

    // ── Client B: dials with the same token, expects reattach ──
    let mut stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cross-repo-resume-b",
        Some(token),
    )
    .await?;
    // Client B mints its own token (the server cannot tell this
    // is a resume until the VLESS handshake confirms ownership);
    // its presence is incidental for this assertion.
    let _issued_b = stream_b.issued_session_id();

    // The handshake target is irrelevant to the resume path —
    // the server uses the parked writer/reader and never reads
    // the target field — but the VLESS parser still needs a
    // syntactically valid one. Pick `helo` so the upstream task
    // can distinguish the two echoes.
    let handshake_b = build_vless_tcp_handshake(upstream_addr, b"helo")?;
    stream_b.send(Message::Binary(Bytes::from(handshake_b))).await?;
    let received_b = read_binary_until_at_least(&mut stream_b, 6).await?;
    assert_eq!(&received_b[..2], &[VERSION, 0x00]);
    assert_eq!(&received_b[2..6], b"ackk", "echo via resumed upstream");

    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

    drop(stream_b);
    server.abort();
    Ok(())
}

// ── h3 (TLS+QUIC) cross-repo tests ─────────────────────────────────────────

/// Spins up a real server with only an h3 (QUIC) listener — no
/// axum/h2. URL → `https://localhost:port/<base_path>`. Mirrors
/// `setup_xhttp_server_with_resumption` from the sibling `xhttp`
/// test module, but binds an `H3WebSocketServer` instead of an
/// axum `serve_listener`. XHTTP routes are dispatched by
/// `crate::server::transport::xhttp::handle_xhttp_h3_request` from
/// inside `serve_h3_server`.
async fn setup_xhttp_h3_server(
    base_path: &'static str,
    resumption: bool,
) -> Result<(SocketAddr, JoinHandle<Result<()>>, Arc<XhttpRegistry>)> {
    super::cross_repo_install_test_tls_root_on_client();
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let tls_config = super::cross_repo_test_server_tls_config(&[b"h3"]);
    let h3_server =
        H3WebSocketServer::<H3Transport>::bind(bind_addr, tls_config, H3WsConfig::default())
            .await?;
    let listen_addr = h3_server.local_addr()?;

    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(TEST_UUID.into(), Arc::from("test"), None)?;
    let xhttp_routes = Arc::new(build_xhttp_vless_route_map(&[VlessXhttpUserRoute {
        user: vless_user,
        xhttp_path: Arc::from(base_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: xhttp_routes,
    }));
    let orphan_registry = if resumption {
        Some(Arc::new(resumption::OrphanRegistry::new(
            resumption::ResumptionConfig::from(&crate::config::SessionResumptionConfig {
                enabled: true,
                orphan_ttl_tcp_secs: 30,
                orphan_ttl_udp_secs: 30,
                orphan_per_user_cap: 4,
                orphan_global_cap: 16,
            }),
            Arc::clone(&metrics),
        )))
    } else {
        None
    };
    let services = Arc::new(Services::new(
        metrics,
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        orphan_registry,
        16,
    ));
    let xhttp_registry = Arc::clone(&services.xhttp_registry);
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });

    let handle = tokio::spawn(async move {
        serve_h3_server(
            h3_server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::H3].into_boxed_slice()),
            Arc::from(Vec::<VlessUser>::new().into_boxed_slice()),
            Arc::from(Vec::<Arc<str>>::new().into_boxed_slice()),
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            ShutdownSignal::never(),
        )
        .await
    });
    Ok((listen_addr, handle, xhttp_registry))
}

#[tokio::test]
async fn cross_repo_xhttp_packet_up_h3_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_h3_server("/xh", false).await?;

    // h3 mandates `https://` on the client; the test's self-signed
    // root was just installed via `install_test_tls_root` so the
    // dial trusts it without touching webpki.
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("https://localhost:{}/xh", listen_addr.port()))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH3,
        None,
        false,
        "cross-repo-h3-test",
        None,
    )
    .await?;

    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    stream.send(Message::Binary(Bytes::from(handshake))).await?;

    let received = read_binary_until_at_least(&mut stream, 6).await?;
    assert_eq!(&received[..2], &[VERSION, 0x00], "vless response header");
    assert_eq!(&received[2..6], b"pong", "echoed payload");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(stream);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn cross_repo_xhttp_stream_one_h3_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server, _registry) = setup_xhttp_h3_server("/xh", false).await?;

    // Stream-one on h3 uses `RequestStream::split` on both ends —
    // the client hands the bidi stream to two concurrent tasks
    // (uplink pump + downlink drain) and the server's
    // `handle_xhttp_h3_request` does the matching split. This test
    // is the only place that exercise reaches in-tree.
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!(
        "https://localhost:{}/xh?mode=stream-one",
        listen_addr.port()
    ))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH3,
        None,
        false,
        "cross-repo-h3-test",
        None,
    )
    .await?;

    let handshake = build_vless_tcp_handshake(upstream_addr, b"ping")?;
    stream.send(Message::Binary(Bytes::from(handshake))).await?;

    let received = read_binary_until_at_least(&mut stream, 6).await?;
    assert_eq!(&received[..2], &[VERSION, 0x00]);
    assert_eq!(&received[2..6], b"pong");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(stream);
    server.abort();
    Ok(())
}
