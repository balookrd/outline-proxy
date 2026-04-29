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
use futures_util::StreamExt;
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
    TransportMode, UpstreamTransportGuard, connect_websocket_with_resume,
};

use super::super::bootstrap::serve_listener;
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
    let app = build_app(routes, services, auth);
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
