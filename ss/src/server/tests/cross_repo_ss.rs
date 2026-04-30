//! Cross-repo end-to-end Shadowsocks integration tests.
//!
//! Companion to `cross_repo_xhttp` and `cross_repo_vless`. Drives
//! the real `outline-ws-rust` client crate through SS-AEAD on two
//! carriers:
//!
//!   * **SS over plain TCP** — the client's
//!     `connect_shadowsocks_tcp_with_source` returns a raw
//!     `TcpStream`; we split it and wrap each half with
//!     `TcpShadowsocksWriter::connect_socket` /
//!     `TcpShadowsocksReader::new_socket`. Server side is the
//!     production `serve_ss_tcp_listener`, exactly the same code
//!     path the running daemon uses.
//!   * **SS over WebSocket-h2** — the client opens a WS upgrade
//!     via `connect_websocket_with_resume(WsH2)`, splits the
//!     resulting `TransportStream` into sink+stream halves, and
//!     wraps with `TcpShadowsocksWriter::connect` /
//!     `TcpShadowsocksReader::new` (the WS-flavoured constructors
//!     that route control frames through the writer's priority
//!     channel). Server side is `build_app` mounting the default
//!     `/tcp` route.
//!
//! Plain-TCP carrier on `http://` / `ws://` URLs avoids TLS
//! plumbing — the dial dispatcher picks `BoxedIo::Plain` whenever
//! the scheme is not `https` / `wss`. Cipher is the `Chacha20IetfPoly1305`
//! default the test config already uses; the master key is derived
//! client-side from the same password the server's `build_users`
//! reads from `sample_config`.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use arc_swap::ArcSwap;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::protocol::Message;
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, WebSocketServer as H3WebSocketServer,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use url::Url;

use outline_transport::{
    CipherKind, DnsCache as ClientDnsCache, TcpShadowsocksReader, TcpShadowsocksWriter,
    TransportMode, UpstreamTransportGuard, connect_ss_tcp_quic, connect_websocket_with_resume,
};

use super::super::bootstrap::serve_listener;
use super::super::resumption::{OrphanRegistry, ResumptionConfig};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, UserKeySlice};
use super::super::{
    DnsCache, Services, SsTcpCtx, UdpServices, build_app, build_user_routes, build_users,
    serve_h3_server, serve_ss_tcp_listener,
};
use super::super::nat::NatTable;
use super::sample_config;
use crate::config::H3Alpn;
use crate::crypto::UserKey;
use crate::metrics::Metrics;
use crate::protocol::TargetAddr;
use crate::protocol::vless::VlessUser;

/// Same password the default `sample_config` user "bob" carries.
/// The server derives the SS master key from this string; the client
/// re-derives an identical one via `CipherKind::derive_master_key`.
const SS_PASSWORD: &str = "secret-b";

/// Spawns a plain-TCP SS listener and returns its bound address.
/// Mirrors `plain_shadowsocks_tcp_relay_smoke` from the existing
/// `shadowsocks` test module — same Services/SsTcpCtx wiring.
async fn setup_ss_plain_tcp_server() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let users = build_users(&config)?;
    let metrics = Metrics::new(&config);
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
        None,
        16,
    ));
    let ctx = SsTcpCtx { users, services };
    let handle = tokio::spawn(async move {
        serve_ss_tcp_listener(listener, ctx, ShutdownSignal::never()).await
    });
    Ok((listen_addr, handle))
}

/// Spawns an axum server with the default `/tcp` SS-over-WS route.
/// `sample_config` already sets `ws_path_tcp: "/tcp"`, so the
/// upgrade handler is wired in by `build_app`.
async fn setup_ss_ws_server() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));
    let (routes, services, auth) = super::build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth, None);
    let handle = tokio::spawn(async move {
        serve_listener(listener, app, ShutdownSignal::never()).await
    });
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_ss_tcp_plain_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_ss_plain_tcp_server().await?;

    // Client side. Plain TCP — no DNS cache used here, but the
    // dial helper takes one, so build a no-op one.
    let _cache = ClientDnsCache::new(Duration::from_secs(30));
    let tcp = TcpStream::connect(listen_addr).await?;
    let (read_half, write_half) = tcp.into_split();

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");
    let lifetime = UpstreamTransportGuard::new("cross-repo-ss", "ss-tcp");

    let mut writer = TcpShadowsocksWriter::connect_socket(
        write_half,
        cipher,
        &master_key,
        Arc::clone(&lifetime),
    )?;
    let mut reader = TcpShadowsocksReader::new_socket(
        read_half,
        cipher,
        &master_key,
        Arc::clone(&lifetime),
    );

    // Legacy AEAD has no separate header frame: the first chunk
    // carries the SOCKS5-style target address followed by the
    // application payload, all encrypted as one AEAD record.
    let mut first = TargetAddr::Socket(upstream_addr).encode()?;
    first.extend_from_slice(b"ping");
    writer.send_chunk(&first).await?;

    let reply = reader.read_chunk().await?;
    assert_eq!(&reply, b"pong", "ss tcp echo over plain TCP");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(reader);
    drop(writer);
    drop(lifetime);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn cross_repo_ss_tcp_ws_h1_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    // Same axum server the h2 test uses — `build_app` mounts both
    // h1 (RFC 6455) and h2 (RFC 8441) flavours of the WebSocket
    // upgrade handler on the same `/tcp` route.
    let (listen_addr, server) = setup_ss_ws_server().await?;

    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("ws://{listen_addr}/tcp"))?;
    let transport_stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH1,
        None,
        false,
        "cross-repo-ss-ws-h1",
        None,
    )
    .await?;
    let (sink, stream) = transport_stream.split();

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");
    let lifetime = UpstreamTransportGuard::new("cross-repo-ss-ws-h1", "ss-ws-h1");

    let (mut writer, ctrl_tx) = TcpShadowsocksWriter::connect(
        sink,
        cipher,
        &master_key,
        Arc::clone(&lifetime),
    )
    .await?;
    let mut reader = TcpShadowsocksReader::new(
        stream,
        cipher,
        &master_key,
        Arc::clone(&lifetime),
        ctrl_tx,
    );

    let mut first = TargetAddr::Socket(upstream_addr).encode()?;
    first.extend_from_slice(b"ping");
    writer.send_chunk(&first).await?;

    let reply = reader.read_chunk().await?;
    assert_eq!(&reply, b"pong", "ss tcp echo over ws-h1");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(reader);
    drop(writer);
    drop(lifetime);
    server.abort();
    Ok(())
}

/// Spins up a real h3-only server (TLS+QUIC) with the default `/tcp`
/// SS-over-WS route mounted via `build_user_routes`. The carrier is
/// RFC 9220 — WebSocket-over-HTTP/3.
async fn setup_ss_ws_h3_server() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    super::cross_repo_install_test_tls_root_on_client();
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let tls_config = super::cross_repo_test_server_tls_config(&[b"h3"]);
    let h3_server =
        H3WebSocketServer::<H3Transport>::bind(bind_addr, tls_config, H3WsConfig::default())
            .await?;
    let listen_addr = h3_server.local_addr()?;

    let config = sample_config(listen_addr);
    let user_routes = build_user_routes(&config)?;
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));
    let (routes, services, auth) = super::build_test_state(
        user_routes,
        metrics,
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );

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
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_ss_tcp_ws_h3_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_ss_ws_h3_server().await?;

    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // WS-h3 mandates `wss://` — same constraint XHTTP h3 tests
    // hit, surfaced in `connect_websocket_h3` itself.
    let url = Url::parse(&format!("wss://localhost:{}/tcp", listen_addr.port()))?;
    let transport_stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH3,
        None,
        false,
        "cross-repo-ss-ws-h3",
        None,
    )
    .await?;
    let (sink, stream) = transport_stream.split();

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");
    let lifetime = UpstreamTransportGuard::new("cross-repo-ss-ws-h3", "ss-ws-h3");

    let (mut writer, ctrl_tx) = TcpShadowsocksWriter::connect(
        sink,
        cipher,
        &master_key,
        Arc::clone(&lifetime),
    )
    .await?;
    let mut reader = TcpShadowsocksReader::new(
        stream,
        cipher,
        &master_key,
        Arc::clone(&lifetime),
        ctrl_tx,
    );

    let mut first = TargetAddr::Socket(upstream_addr).encode()?;
    first.extend_from_slice(b"ping");
    writer.send_chunk(&first).await?;

    let reply = reader.read_chunk().await?;
    assert_eq!(&reply, b"pong", "ss tcp echo over ws-h3");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(reader);
    drop(writer);
    drop(lifetime);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn cross_repo_ss_tcp_ws_h2_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_ss_ws_server().await?;

    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // `ws://` keeps the dial on plain TCP h2; the server's axum
    // route mounted by `build_app` is identical to production.
    let url = Url::parse(&format!("ws://{listen_addr}/tcp"))?;
    let transport_stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-ss-ws",
        None,
    )
    .await?;
    let (sink, stream) = transport_stream.split();

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");
    let lifetime = UpstreamTransportGuard::new("cross-repo-ss-ws", "ss-ws-h2");

    let (mut writer, ctrl_tx) = TcpShadowsocksWriter::connect(
        sink,
        cipher,
        &master_key,
        Arc::clone(&lifetime),
    )
    .await?;
    let mut reader = TcpShadowsocksReader::new(
        stream,
        cipher,
        &master_key,
        Arc::clone(&lifetime),
        ctrl_tx,
    );

    let mut first = TargetAddr::Socket(upstream_addr).encode()?;
    first.extend_from_slice(b"ping");
    writer.send_chunk(&first).await?;

    let reply = reader.read_chunk().await?;
    assert_eq!(&reply, b"pong", "ss tcp echo over ws-h2");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(reader);
    drop(writer);
    drop(lifetime);
    server.abort();
    Ok(())
}

// ── Cross-transport session resumption ─────────────────────────────────────

/// Variant of [`setup_ss_ws_server`] with `OrphanRegistry`
/// enabled. The SS-over-WebSocket upgrade handler reads
/// `X-Outline-Resume-Capable` / `X-Outline-Resume` from the upgrade
/// request and writes `X-Outline-Session` on the response, exactly
/// like the production listener; on a clean WS Close the relay
/// parks the live SS upstream into the registry under the issued
/// token.
async fn setup_ss_ws_server_with_resumption() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));
    let metrics = Metrics::new(&config);

    let users = super::user_keys(user_routes.as_ref());
    let tcp = Arc::new(super::super::build_transport_route_map(
        user_routes.as_ref(),
        crate::metrics::Transport::Tcp,
    ));
    let udp = Arc::new(super::super::build_transport_route_map(
        user_routes.as_ref(),
        crate::metrics::Transport::Udp,
    ));
    let vless = Arc::new(super::super::setup::build_vless_transport_route_map(&[]));
    let xhttp_vless = Arc::new(BTreeMap::new());
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp,
        udp,
        vless,
        xhttp_vless,
    }));
    let orphan_registry = Some(Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&crate::config::SessionResumptionConfig {
            enabled: true,
            orphan_ttl_tcp_secs: 30,
            orphan_ttl_udp_secs: 30,
            orphan_per_user_cap: 4,
            orphan_global_cap: 16,
        }),
        Arc::clone(&metrics),
    )));
    let services = Arc::new(Services::new(
        metrics,
        dns_cache,
        false,
        None,
        UdpServices {
            nat_table,
            replay_store: super::super::replay::ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        orphan_registry,
        16,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth: false,
        http_root_realm: Arc::from(config.http_root_realm.as_str()),
    });
    let app = build_app(routes, services, auth, None);
    let handle = tokio::spawn(async move {
        serve_listener(listener, app, ShutdownSignal::never()).await
    });
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_ss_tcp_ws_h2_resume_reattaches_parked_upstream() -> Result<()> {
    // Echo upstream that handles two read/reply rounds on a single
    // accepted socket — resume preserves the upstream across the
    // client-A → client-B switch.
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

    let (listen_addr, server) = setup_ss_ws_server_with_resumption().await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("ws://{listen_addr}/tcp"))?;

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");

    // ── Client A: capability advertise + first round-trip ──────
    let stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-ss-ws-h2-resume-a",
        None,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;
    let (sink_a, stream_a_inner) = stream_a.split();
    let lifetime_a = UpstreamTransportGuard::new("cross-repo-ss-ws-h2-resume-a", "ss-ws-h2");
    let (mut writer_a, ctrl_tx_a) = TcpShadowsocksWriter::connect(
        sink_a,
        cipher,
        &master_key,
        Arc::clone(&lifetime_a),
    )
    .await?;
    let mut reader_a = TcpShadowsocksReader::new(
        stream_a_inner,
        cipher,
        &master_key,
        Arc::clone(&lifetime_a),
        ctrl_tx_a.clone(),
    );

    let mut first_payload = TargetAddr::Socket(upstream_addr).encode()?;
    first_payload.extend_from_slice(b"ping");
    writer_a.send_chunk(&first_payload).await?;
    let reply_a = reader_a.read_chunk().await?;
    assert_eq!(&reply_a, b"pong");

    // Send a graceful Close frame through the writer's priority
    // channel so the server's WS reader sees a clean shutdown — a
    // bare `drop(writer)` would `AbortOnDrop` the writer task
    // before it can flush the Close, propagate as h2 RST_STREAM,
    // and the relay would treat it as an error and tear the
    // upstream down instead of parking it. The 100 ms wait gives
    // the writer task time to actually push the Close onto the
    // wire before AbortOnDrop fires.
    let _ = ctrl_tx_a.send(Message::Close(None)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(reader_a);
    drop(writer_a);
    drop(ctrl_tx_a);
    drop(lifetime_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: dials with the same token, expects reattach ──
    let stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-ss-ws-h2-resume-b",
        Some(token),
    )
    .await?;
    let _issued_b = stream_b.issued_session_id();
    let (sink_b, stream_b_inner) = stream_b.split();
    let lifetime_b = UpstreamTransportGuard::new("cross-repo-ss-ws-h2-resume-b", "ss-ws-h2");
    let (mut writer_b, ctrl_tx_b) = TcpShadowsocksWriter::connect(
        sink_b,
        cipher,
        &master_key,
        Arc::clone(&lifetime_b),
    )
    .await?;
    let mut reader_b = TcpShadowsocksReader::new(
        stream_b_inner,
        cipher,
        &master_key,
        Arc::clone(&lifetime_b),
        ctrl_tx_b.clone(),
    );

    // Target is irrelevant on the resume path; the server uses the
    // parked upstream and never re-resolves. Pick `helo` so the
    // upstream task can distinguish the two reads.
    let mut second_payload = TargetAddr::Socket(upstream_addr).encode()?;
    second_payload.extend_from_slice(b"helo");
    writer_b.send_chunk(&second_payload).await?;
    let reply_b = reader_b.read_chunk().await?;
    assert_eq!(&reply_b, b"ackk", "ss tcp echo via resumed upstream");

    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

    drop(reader_b);
    drop(writer_b);
    drop(ctrl_tx_b);
    drop(lifetime_b);
    server.abort();
    Ok(())
}

/// Same as [`setup_ss_ws_h3_server`] but with `OrphanRegistry`
/// enabled. Mirrors `setup_ss_ws_server_with_resumption` but binds
/// an `H3WebSocketServer` so the WS upgrade rides QUIC (RFC 9220)
/// instead of plain TCP h2.
async fn setup_ss_ws_h3_server_with_resumption()
-> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    super::cross_repo_install_test_tls_root_on_client();
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let tls_config = super::cross_repo_test_server_tls_config(&[b"h3"]);
    let h3_server =
        H3WebSocketServer::<H3Transport>::bind(bind_addr, tls_config, H3WsConfig::default())
            .await?;
    let listen_addr = h3_server.local_addr()?;

    let config = sample_config(listen_addr);
    let user_routes = build_user_routes(&config)?;
    let metrics = Metrics::new(&config);

    let users = super::user_keys(user_routes.as_ref());
    let tcp = Arc::new(super::super::build_transport_route_map(
        user_routes.as_ref(),
        crate::metrics::Transport::Tcp,
    ));
    let udp = Arc::new(super::super::build_transport_route_map(
        user_routes.as_ref(),
        crate::metrics::Transport::Udp,
    ));
    let vless = Arc::new(super::super::setup::build_vless_transport_route_map(&[]));
    let xhttp_vless = Arc::new(BTreeMap::new());
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp,
        udp,
        vless,
        xhttp_vless,
    }));
    let orphan_registry = Some(Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&crate::config::SessionResumptionConfig {
            enabled: true,
            orphan_ttl_tcp_secs: 30,
            orphan_ttl_udp_secs: 30,
            orphan_per_user_cap: 4,
            orphan_global_cap: 16,
        }),
        Arc::clone(&metrics),
    )));
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
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth: false,
        http_root_realm: Arc::from(config.http_root_realm.as_str()),
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
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_ss_tcp_ws_h3_resume_reattaches_parked_upstream() -> Result<()> {
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

    let (listen_addr, server) = setup_ss_ws_h3_server_with_resumption().await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("wss://localhost:{}/tcp", listen_addr.port()))?;

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");

    // ── Client A ───────────────────────────────────────────────
    let stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH3,
        None,
        false,
        "cross-repo-ss-ws-h3-resume-a",
        None,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;
    let (sink_a, stream_a_inner) = stream_a.split();
    let lifetime_a = UpstreamTransportGuard::new("cross-repo-ss-ws-h3-resume-a", "ss-ws-h3");
    let (mut writer_a, ctrl_tx_a) = TcpShadowsocksWriter::connect(
        sink_a,
        cipher,
        &master_key,
        Arc::clone(&lifetime_a),
    )
    .await?;
    let mut reader_a = TcpShadowsocksReader::new(
        stream_a_inner,
        cipher,
        &master_key,
        Arc::clone(&lifetime_a),
        ctrl_tx_a.clone(),
    );

    let mut first_payload = TargetAddr::Socket(upstream_addr).encode()?;
    first_payload.extend_from_slice(b"ping");
    writer_a.send_chunk(&first_payload).await?;
    let reply_a = reader_a.read_chunk().await?;
    assert_eq!(&reply_a, b"pong");

    // Same Close-then-wait dance the h2 path needs — `AbortOnDrop`
    // on the writer task would otherwise kill the spawn before the
    // QUIC bidi stream's Close frame hits the wire.
    let _ = ctrl_tx_a.send(Message::Close(None)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(reader_a);
    drop(writer_a);
    drop(ctrl_tx_a);
    drop(lifetime_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B ───────────────────────────────────────────────
    let stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH3,
        None,
        false,
        "cross-repo-ss-ws-h3-resume-b",
        Some(token),
    )
    .await?;
    let _issued_b = stream_b.issued_session_id();
    let (sink_b, stream_b_inner) = stream_b.split();
    let lifetime_b = UpstreamTransportGuard::new("cross-repo-ss-ws-h3-resume-b", "ss-ws-h3");
    let (mut writer_b, ctrl_tx_b) = TcpShadowsocksWriter::connect(
        sink_b,
        cipher,
        &master_key,
        Arc::clone(&lifetime_b),
    )
    .await?;
    let mut reader_b = TcpShadowsocksReader::new(
        stream_b_inner,
        cipher,
        &master_key,
        Arc::clone(&lifetime_b),
        ctrl_tx_b.clone(),
    );

    let mut second_payload = TargetAddr::Socket(upstream_addr).encode()?;
    second_payload.extend_from_slice(b"helo");
    writer_b.send_chunk(&second_payload).await?;
    let reply_b = reader_b.read_chunk().await?;
    assert_eq!(&reply_b, b"ackk", "ss tcp echo via resumed upstream");

    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

    drop(reader_b);
    drop(writer_b);
    drop(ctrl_tx_b);
    drop(lifetime_b);
    server.abort();
    Ok(())
}

/// Variant of [`setup_ss_ws_server`] over TLS+TCP only (no QUIC) with
/// `OrphanRegistry` enabled. Pointing client B at the same `wss://`
/// URL while no UDP listener exists drives the dispatcher's WS-h3 →
/// WS-h2 fallback path with the resume token preserved end-to-end.
async fn setup_ss_ws_h2_tls_server_with_resumption()
-> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    super::cross_repo_install_test_tls_root_on_client();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let user_routes = build_user_routes(&config)?;
    let metrics = Metrics::new(&config);

    let users = super::user_keys(user_routes.as_ref());
    let tcp = Arc::new(super::super::build_transport_route_map(
        user_routes.as_ref(),
        crate::metrics::Transport::Tcp,
    ));
    let udp = Arc::new(super::super::build_transport_route_map(
        user_routes.as_ref(),
        crate::metrics::Transport::Udp,
    ));
    let vless = Arc::new(super::super::setup::build_vless_transport_route_map(&[]));
    let xhttp_vless = Arc::new(BTreeMap::new());
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp,
        udp,
        vless,
        xhttp_vless,
    }));
    let orphan_registry = Some(Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&crate::config::SessionResumptionConfig {
            enabled: true,
            orphan_ttl_tcp_secs: 30,
            orphan_ttl_udp_secs: 30,
            orphan_per_user_cap: 4,
            orphan_global_cap: 16,
        }),
        Arc::clone(&metrics),
    )));
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
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth: false,
        http_root_realm: Arc::from(config.http_root_realm.as_str()),
    });
    let app = build_app(routes, services, auth, None);

    let server_tls = super::cross_repo_test_server_tls_config(&[b"h2", b"http/1.1"]);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));

    let handle = tokio::spawn(super::cross_repo_serve_axum_with_tls(listener, app, acceptor));
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_ss_tcp_ws_h3_to_h2_fallback_with_resume_token() -> Result<()> {
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

    let (listen_addr, server) = setup_ss_ws_h2_tls_server_with_resumption().await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("wss://localhost:{}/tcp", listen_addr.port()))?;

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");

    // ── Client A: WsH2 over TLS ───────────────────────────────
    let stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-ss-fallback-a",
        None,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;
    let (sink_a, stream_a_inner) = stream_a.split();
    let lifetime_a = UpstreamTransportGuard::new("cross-repo-ss-fallback-a", "ss-ws-h2");
    let (mut writer_a, ctrl_tx_a) = TcpShadowsocksWriter::connect(
        sink_a,
        cipher,
        &master_key,
        Arc::clone(&lifetime_a),
    )
    .await?;
    let mut reader_a = TcpShadowsocksReader::new(
        stream_a_inner,
        cipher,
        &master_key,
        Arc::clone(&lifetime_a),
        ctrl_tx_a.clone(),
    );

    let mut first_payload = TargetAddr::Socket(upstream_addr).encode()?;
    first_payload.extend_from_slice(b"ping");
    writer_a.send_chunk(&first_payload).await?;
    let reply_a = reader_a.read_chunk().await?;
    assert_eq!(&reply_a, b"pong");

    let _ = ctrl_tx_a.send(Message::Close(None)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(reader_a);
    drop(writer_a);
    drop(ctrl_tx_a);
    drop(lifetime_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: WsH3 → 10 s timeout → fallback to WsH2 ──────
    let stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH3,
        None,
        false,
        "cross-repo-ss-fallback-b",
        Some(token),
    )
    .await?;
    assert_eq!(
        stream_b.downgraded_from(),
        Some(TransportMode::WsH3),
        "client B should report a downgrade from WsH3",
    );
    let _issued_b = stream_b.issued_session_id();
    let (sink_b, stream_b_inner) = stream_b.split();
    let lifetime_b = UpstreamTransportGuard::new("cross-repo-ss-fallback-b", "ss-ws-h2");
    let (mut writer_b, ctrl_tx_b) = TcpShadowsocksWriter::connect(
        sink_b,
        cipher,
        &master_key,
        Arc::clone(&lifetime_b),
    )
    .await?;
    let mut reader_b = TcpShadowsocksReader::new(
        stream_b_inner,
        cipher,
        &master_key,
        Arc::clone(&lifetime_b),
        ctrl_tx_b.clone(),
    );

    let mut second_payload = TargetAddr::Socket(upstream_addr).encode()?;
    second_payload.extend_from_slice(b"helo");
    writer_b.send_chunk(&second_payload).await?;
    let reply_b = reader_b.read_chunk().await?;
    assert_eq!(&reply_b, b"ackk", "ss tcp echo via resumed upstream");

    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

    drop(reader_b);
    drop(writer_b);
    drop(ctrl_tx_b);
    drop(lifetime_b);
    server.abort();
    Ok(())
}

/// Plain-TCP, h1-only axum server with `OrphanRegistry` enabled —
/// the SS-WS counterpart to `setup_ss_ws_h2_tls_server_with_resumption`.
/// Drives the dispatcher's WS-h2 → WS-h1 fallback path: the WsH2
/// dial writes the h2 preface, hyper's h1 codec rejects it as a
/// malformed h1 request, and the client retries on h1 with the
/// same `X-Outline-Resume` header. Plain TCP avoids the
/// tungstenite-vs-override-slot mismatch the h1 path would have
/// over TLS.
async fn setup_ss_ws_h1_only_server_with_resumption()
-> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let user_routes = build_user_routes(&config)?;
    let metrics = Metrics::new(&config);

    let users = super::user_keys(user_routes.as_ref());
    let tcp = Arc::new(super::super::build_transport_route_map(
        user_routes.as_ref(),
        crate::metrics::Transport::Tcp,
    ));
    let udp = Arc::new(super::super::build_transport_route_map(
        user_routes.as_ref(),
        crate::metrics::Transport::Udp,
    ));
    let vless = Arc::new(super::super::setup::build_vless_transport_route_map(&[]));
    let xhttp_vless = Arc::new(BTreeMap::new());
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp,
        udp,
        vless,
        xhttp_vless,
    }));
    let orphan_registry = Some(Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&crate::config::SessionResumptionConfig {
            enabled: true,
            orphan_ttl_tcp_secs: 30,
            orphan_ttl_udp_secs: 30,
            orphan_per_user_cap: 4,
            orphan_global_cap: 16,
        }),
        Arc::clone(&metrics),
    )));
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
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth: false,
        http_root_realm: Arc::from(config.http_root_realm.as_str()),
    });
    let app = build_app(routes, services, auth, None);

    let handle = tokio::spawn(super::cross_repo_serve_axum_h1_only(listener, app));
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_ss_tcp_ws_h2_to_h1_fallback_with_resume_token() -> Result<()> {
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

    let (listen_addr, server) = setup_ss_ws_h1_only_server_with_resumption().await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("ws://{listen_addr}/tcp"))?;

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");

    // ── Client A: WsH1 over plain TCP — gets the resume token ──
    let stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH1,
        None,
        false,
        "cross-repo-ss-h2-h1-fallback-a",
        None,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;
    let (sink_a, stream_a_inner) = stream_a.split();
    let lifetime_a = UpstreamTransportGuard::new("cross-repo-ss-h2-h1-fallback-a", "ss-ws-h1");
    let (mut writer_a, ctrl_tx_a) = TcpShadowsocksWriter::connect(
        sink_a,
        cipher,
        &master_key,
        Arc::clone(&lifetime_a),
    )
    .await?;
    let mut reader_a = TcpShadowsocksReader::new(
        stream_a_inner,
        cipher,
        &master_key,
        Arc::clone(&lifetime_a),
        ctrl_tx_a.clone(),
    );

    let mut first_payload = TargetAddr::Socket(upstream_addr).encode()?;
    first_payload.extend_from_slice(b"ping");
    writer_a.send_chunk(&first_payload).await?;
    let reply_a = reader_a.read_chunk().await?;
    assert_eq!(&reply_a, b"pong");

    // Same graceful-Close dance as the h3→h2 fallback test: send a
    // Close frame through the writer's priority channel (a bare
    // `drop(writer)` would AbortOnDrop the writer task before it
    // flushes the Close, the relay would then see the carrier RST
    // as an error and tear the upstream down instead of parking it).
    let _ = ctrl_tx_a.send(Message::Close(None)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(reader_a);
    drop(writer_a);
    drop(ctrl_tx_a);
    drop(lifetime_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: WsH2 → h2 handshake fails → fallback to WsH1 ─
    let stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-ss-h2-h1-fallback-b",
        Some(token),
    )
    .await?;
    assert_eq!(
        stream_b.downgraded_from(),
        Some(TransportMode::WsH2),
        "client B should report a downgrade from WsH2",
    );
    let _issued_b = stream_b.issued_session_id();
    let (sink_b, stream_b_inner) = stream_b.split();
    let lifetime_b = UpstreamTransportGuard::new("cross-repo-ss-h2-h1-fallback-b", "ss-ws-h1");
    let (mut writer_b, ctrl_tx_b) = TcpShadowsocksWriter::connect(
        sink_b,
        cipher,
        &master_key,
        Arc::clone(&lifetime_b),
    )
    .await?;
    let mut reader_b = TcpShadowsocksReader::new(
        stream_b_inner,
        cipher,
        &master_key,
        Arc::clone(&lifetime_b),
        ctrl_tx_b.clone(),
    );

    let mut second_payload = TargetAddr::Socket(upstream_addr).encode()?;
    second_payload.extend_from_slice(b"helo");
    writer_b.send_chunk(&second_payload).await?;
    let reply_b = reader_b.read_chunk().await?;
    assert_eq!(&reply_b, b"ackk", "ss tcp echo via resumed upstream");

    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

    drop(reader_b);
    drop(writer_b);
    drop(ctrl_tx_b);
    drop(lifetime_b);
    server.abort();
    Ok(())
}

/// Spins up a raw-QUIC server with the `ss` ALPN. Mirrors
/// `setup_vless_raw_quic_server` from `cross_repo_vless` but
/// populates `raw_ss_users` from `build_users(&sample_config)` and
/// leaves the VLESS slots empty. The server reads SS-AEAD off the
/// QUIC bidi stream exactly as the plain-TCP listener does — the
/// `unit raw_quic::ss_raw_quic_tcp_relay_smoke` test exercises the
/// same path with a hand-rolled QUIC client; this cross-repo test
/// drives it through `outline_transport::connect_ss_tcp_quic`.
async fn setup_ss_raw_quic_server() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    super::cross_repo_install_test_tls_root_on_client();
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    // Client offers `[ss-mtu, ss]` (MTU-aware first); the server
    // mirrors so negotiation lands on `ss-mtu` when the path
    // supports it and on `ss` otherwise.
    let tls_config = super::cross_repo_test_server_tls_config(&[b"ss-mtu", b"ss"]);
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|_| anyhow::anyhow!("invalid raw-quic test TLS config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let mut transport = quinn::TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(1 << 20))
        .datagram_send_buffer_size(1 << 20);
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    let server = H3WebSocketServer::<H3Transport>::from_endpoint(endpoint, H3WsConfig::default());
    let listen_addr = server.local_addr()?;

    let config = sample_config(listen_addr);
    let users = build_users(&config)?;
    let metrics = Metrics::new(&config);

    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: Arc::new(BTreeMap::new()),
    }));
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
        None,
        16,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });

    let handle = tokio::spawn(async move {
        serve_h3_server(
            server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::Ss].into_boxed_slice()),
            Arc::from(Vec::<VlessUser>::new().into_boxed_slice()),
            Arc::from(Vec::<Arc<str>>::new().into_boxed_slice()),
            users,
            ShutdownSignal::never(),
        )
        .await
    });
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_ss_tcp_raw_quic_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_ss_raw_quic_server().await?;

    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // Same shape as the VLESS raw-QUIC test: `https://` is required
    // because raw QUIC is TLS-only, the path is ignored, and ALPN
    // selection happens inside `connect_ss_tcp_quic`.
    let url = Url::parse(&format!("https://localhost:{}/", listen_addr.port()))?;

    let cipher = CipherKind::Chacha20IetfPoly1305;
    let master_key = cipher
        .derive_master_key(SS_PASSWORD)
        .expect("derive_master_key succeeds for chacha20");
    let lifetime = UpstreamTransportGuard::new("cross-repo-ss-quic", "ss-quic");

    let (mut writer, mut reader) = connect_ss_tcp_quic(
        &cache,
        &url,
        None,
        false,
        "cross-repo-ss-quic",
        cipher,
        &master_key,
        Arc::clone(&lifetime),
    )
    .await?;

    // Same wire form as the plain-TCP / WS-h2 SS tests: the first
    // chunk carries `target_addr || payload`, and `read_chunk()`
    // returns just the upstream bytes (target prefix is consumed by
    // the relay).
    let mut first_payload = TargetAddr::Socket(upstream_addr).encode()?;
    first_payload.extend_from_slice(b"ping");
    writer.send_chunk(&first_payload).await?;
    let reply = reader.read_chunk().await?;
    assert_eq!(&reply, b"pong");

    let upstream_bytes =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&upstream_bytes, b"ping");

    drop(reader);
    drop(writer);
    drop(lifetime);
    server.abort();
    Ok(())
}
