//! Cross-repo end-to-end VLESS integration tests.
//!
//! Companion to `cross_repo_xhttp` — same idea (drive the real
//! `outline-ws-rust` client crate against this server in a single
//! tokio process), but covers the WebSocket and raw-QUIC carriers
//! that XHTTP does not exercise.
//!
//! Two tests live here:
//!   * **VLESS-TCP over WebSocket-h2 plain TCP.** Server mounts the
//!     same axum vless route the production listener uses; client
//!     dials via `connect_websocket_with_resume(WsH2)`, gets a
//!     `TransportStream::H2`, and sends the VLESS handshake as a
//!     binary frame. Verifies the wire-form agreement on the
//!     WebSocket-over-h2 carrier without any TLS plumbing — the
//!     scheme `http://` keeps the dial on plain TCP.
//!   * **VLESS-TCP over raw QUIC.** Server binds an `H3WebSocketServer`
//!     with the `vless` ALPN; client dials via
//!     `connect_vless_tcp_quic_with_resume`, which negotiates the
//!     same ALPN and then frames the VLESS request on a fresh
//!     bidi stream. Self-signed cert is shared with the xhttp h3
//!     tests through the helpers in `tests/mod.rs`.

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
    DnsCache as ClientDnsCache, TargetAddr, TransportMode, TransportStream,
    UpstreamTransportGuard, connect_vless_tcp_quic_with_resume, connect_websocket_with_resume,
    vless::vless_tcp_pair_from_ws,
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::resumption::{OrphanRegistry, ResumptionConfig};
use super::super::setup::{VlessUserRoute, build_vless_transport_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, Services, UdpServices, UserKeySlice};
use super::super::{DnsCache, build_app, serve_h3_server};
// no extra import needed — the helpers live in tests/mod.rs as `super::*`.
use super::sample_config;
use crate::config::H3Alpn;
use crate::crypto::UserKey;
use crate::metrics::Metrics;
use crate::protocol::vless::{VERSION, VlessUser, parse_uuid};

const TEST_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

/// Read binary frames from a `TransportStream` until at least
/// `expected` bytes have been gathered. Mirrors the helper in
/// `cross_repo_xhttp.rs`; lifted here verbatim because the WebSocket
/// `TransportStream` variants split chunks identically (VLESS
/// response header + first downlink payload usually arrive in two
/// frames).
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

/// Spins up a real axum server with one VLESS-over-WebSocket route at
/// `ws_path`. Mirrors `setup_xhttp_server` from the sibling xhttp
/// test module — same Services/AuthPolicy shape, plain TCP listener
/// (no TLS), VLESS user keyed by `TEST_UUID`.
async fn setup_vless_ws_server(
    ws_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(TEST_UUID.into(), Arc::from("test"), None)?;
    let vless_routes = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: vless_user,
        ws_path: Arc::from(ws_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
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
    let app = build_app(routes, services, auth, None);
    let handle = tokio::spawn(async move {
        serve_listener(listener, app, ShutdownSignal::never()).await
    });
    Ok((listen_addr, handle))
}

/// Spins up a raw-QUIC server with the `vless` ALPN. Reuses the
/// shared cross-repo cert helpers in `tests/mod.rs` so client and
/// server end up trusting the same self-signed root. The server
/// path goes through `serve_h3_server` exactly the same way the
/// production binary does — `H3Alpn::Vless` selects the raw-QUIC
/// dispatch and `xhttp_vless` is empty (we're not testing XHTTP
/// here).
async fn setup_vless_raw_quic_server() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    super::cross_repo_install_test_tls_root_on_client();
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    // The client offers `[vless-mtu, vless]` ALPNs (MTU-aware first);
    // the server has to advertise both for the negotiation to pick
    // the MTU-aware variant when available.
    let tls_config = super::cross_repo_test_server_tls_config(&[b"vless-mtu", b"vless"]);
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
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(TEST_UUID.into(), Arc::from("test"), None)?;
    let raw_vless_users: Arc<[VlessUser]> = Arc::from(vec![vless_user.clone()].into_boxed_slice());
    let raw_vless_candidates: Arc<[Arc<str>]> =
        Arc::from(vec![vless_user.label_arc()].into_boxed_slice());

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
            Arc::from(vec![H3Alpn::Vless].into_boxed_slice()),
            raw_vless_users,
            raw_vless_candidates,
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            None,
            ShutdownSignal::never(),
        )
        .await
    });
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_vless_tcp_ws_h2_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_vless_ws_server("/vless").await?;

    // `ws://` keeps the WS-h2 dial on plain TCP (tungstenite refuses
    // `http://` even though they're wire-equivalent for the upgrade
    // request). XHTTP can use `http://` because its dispatcher
    // bypasses tungstenite's URL validator entirely.
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("ws://{listen_addr}/vless"))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-vless-ws",
        None,
        false,
    )
    .await?;

    // Build the VLESS handshake the same way the existing
    // `vless::vless_websocket_tcp_relay_smoke` test does and ship it
    // in one binary frame.
    let mut handshake = Vec::new();
    handshake.push(VERSION);
    handshake.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake.push(0); // no addons
    handshake.push(crate::protocol::vless::COMMAND_TCP);
    handshake.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake.push(0x01); // IPv4
    handshake.extend_from_slice(&[127, 0, 0, 1]);
    handshake.extend_from_slice(b"ping");
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
async fn cross_repo_vless_tcp_ws_h1_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    // Same axum server the h2 test mounts — it accepts both h1 and
    // h2 upgrade flavours since `build_app` doesn't gate on version.
    let (listen_addr, server) = setup_vless_ws_server("/vless").await?;

    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("ws://{listen_addr}/vless"))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH1,
        None,
        false,
        "cross-repo-vless-ws-h1",
        None,
        false,
    )
    .await?;

    let mut handshake = Vec::new();
    handshake.push(VERSION);
    handshake.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake.push(0);
    handshake.push(crate::protocol::vless::COMMAND_TCP);
    handshake.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake.push(0x01);
    handshake.extend_from_slice(&[127, 0, 0, 1]);
    handshake.extend_from_slice(b"ping");
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

/// Spins up a real h3-only server (TLS+QUIC) with one VLESS-over-WS
/// route mounted at `/vless`. The carrier is RFC 9220 — WebSocket
/// over HTTP/3 CONNECT extended — driven by `serve_h3_server`'s
/// existing dispatch.
async fn setup_vless_ws_h3_server(
    ws_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
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
    let vless_routes = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: vless_user,
        ws_path: Arc::from(ws_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
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
            h3_server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::H3].into_boxed_slice()),
            Arc::from(Vec::<VlessUser>::new().into_boxed_slice()),
            Arc::from(Vec::<Arc<str>>::new().into_boxed_slice()),
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            None,
            ShutdownSignal::never(),
        )
        .await
    });
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_vless_tcp_ws_h3_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_vless_ws_h3_server("/vless").await?;

    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // WS-h3 mandates `wss://` (the client bails on anything else
    // before it even tries the QUIC dial).
    let url = Url::parse(&format!("wss://localhost:{}/vless", listen_addr.port()))?;
    let mut stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH3,
        None,
        false,
        "cross-repo-vless-ws-h3",
        None,
        false,
    )
    .await?;

    let mut handshake = Vec::new();
    handshake.push(VERSION);
    handshake.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake.push(0);
    handshake.push(crate::protocol::vless::COMMAND_TCP);
    handshake.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake.push(0x01);
    handshake.extend_from_slice(&[127, 0, 0, 1]);
    handshake.extend_from_slice(b"ping");
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
async fn cross_repo_vless_tcp_raw_quic_round_trip() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    let (listen_addr, server) = setup_vless_raw_quic_server().await?;

    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // Raw QUIC uses the URL only for `host:port`; the path is
    // ignored. ALPN `vless` is what the dialer sends. The scheme
    // must be `https://` because raw QUIC is TLS-only.
    let url = Url::parse(&format!("https://localhost:{}/", listen_addr.port()))?;
    let uuid_bytes: [u8; 16] = parse_uuid(TEST_UUID)?
        .try_into()
        .expect("UUID parses to 16 bytes");
    let target = TargetAddr::IpV4(Ipv4Addr::LOCALHOST, upstream_addr.port());
    let lifetime = UpstreamTransportGuard::new("cross-repo-vless-quic", "vless");

    let (mut writer, mut reader, _resume_rx) = connect_vless_tcp_quic_with_resume(
        &cache,
        &url,
        None,
        false,
        "cross-repo-vless-quic",
        &uuid_bytes,
        &target,
        Arc::clone(&lifetime),
        None,
    )
    .await?;

    // The dial flushes the request header eagerly but does NOT send
    // any payload — push `ping` ourselves so the relay forwards it
    // upstream.
    writer.send_chunk(b"ping").await?;
    // First chunk back consumes the VLESS response header
    // internally; the bytes returned are the upstream payload only.
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

// ── Cross-transport session resumption ─────────────────────────────────────

/// Variant of [`setup_vless_ws_server`] that wires a real
/// [`OrphanRegistry`] into `Services`. With it, the WS-upgrade
/// handler mints `X-Outline-Session` on first contact and parks
/// the live VLESS upstream under that token when the WS stream
/// closes; a subsequent dial carrying `X-Outline-Resume: <hex>`
/// reattaches to the parked upstream instead of opening a fresh
/// TCP connection. Without resumption the registry is the
/// disabled stub and `issued_session_id()` is `None`.
async fn setup_vless_ws_server_with_resumption(
    ws_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(TEST_UUID.into(), Arc::from("test"), None)?;
    let vless_routes = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: vless_user,
        ws_path: Arc::from(ws_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
        xhttp_vless: Arc::new(BTreeMap::new()),
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
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth, None);
    let handle = tokio::spawn(async move {
        serve_listener(listener, app, ShutdownSignal::never()).await
    });
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_vless_tcp_ws_h2_resume_reattaches_parked_upstream() -> Result<()> {
    // Echo upstream that handles two read/reply rounds on a single
    // accepted socket — the resume contract preserves the upstream
    // across the client-A → client-B switch.
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

    let (listen_addr, server) = setup_vless_ws_server_with_resumption("/vless").await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("ws://{listen_addr}/vless"))?;

    // ── Client A: capability advertise + first round-trip ──────
    let mut stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-vless-ws-h2-resume-a",
        None,
        false,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;

    let mut handshake_a = Vec::new();
    handshake_a.push(VERSION);
    handshake_a.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_a.push(0);
    handshake_a.push(crate::protocol::vless::COMMAND_TCP);
    handshake_a.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_a.push(0x01);
    handshake_a.extend_from_slice(&[127, 0, 0, 1]);
    handshake_a.extend_from_slice(b"ping");
    stream_a
        .send(Message::Binary(Bytes::from(handshake_a)))
        .await?;
    let received_a = read_binary_until_at_least(&mut stream_a, 6).await?;
    assert_eq!(&received_a[..2], &[VERSION, 0x00]);
    assert_eq!(&received_a[2..6], b"pong");

    // Send an explicit Close frame so the server's WS reader sees
    // a graceful shutdown and the relay's park-on-disconnect path
    // stashes the live upstream into the orphan registry. A bare
    // `drop(stream)` would surface as an h2 RST_STREAM, which the
    // relay treats as an error and tears the upstream down.
    use futures_util::SinkExt;
    let _ = stream_a.send(Message::Close(None)).await;
    let _ = stream_a.close().await;
    drop(stream_a);
    // The relay needs a moment to break out of its read loop and
    // shove the upstream into the registry; without this sleep
    // client B's resume can race the park and miss it.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: dials with the same token, expects reattach ──
    let mut stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-vless-ws-h2-resume-b",
        Some(token),
        false,
    )
    .await?;
    let _issued_b = stream_b.issued_session_id();

    // The handshake target is irrelevant on the resume path —
    // the server uses the parked writer/reader and never reads
    // the target field — but the VLESS parser still needs a
    // syntactically valid one. Pick `helo` to distinguish the
    // upstream's two reads.
    let mut handshake_b = Vec::new();
    handshake_b.push(VERSION);
    handshake_b.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_b.push(0);
    handshake_b.push(crate::protocol::vless::COMMAND_TCP);
    handshake_b.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_b.push(0x01);
    handshake_b.extend_from_slice(&[127, 0, 0, 1]);
    handshake_b.extend_from_slice(b"helo");
    stream_b
        .send(Message::Binary(Bytes::from(handshake_b)))
        .await?;
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

/// End-to-end check of the v1.1 Ack-Prefix Protocol on the VLESS-WS
/// path — companion to `cross_repo_ss_tcp_ws_h2_ack_prefix_reports
/// _up_acked_offset` in `cross_repo_ss.rs`.
///
/// Drives client A through one round-trip without the capability,
/// parks the upstream on a clean WS Close, then reconnects as
/// client B with both `X-Outline-Resume: <token>` AND
/// `X-Outline-Resume-Ack-Prefix: 1`. Asserts:
///
///   1. The server echoes the capability header on the resume hit.
///   2. `consume_ack_prefix_with_timeout` on the client's
///      `VlessTcpReader` returns the parsed offset BEFORE any data
///      `read_chunk` runs (proves the v1.1 fast path works for
///      VLESS).
///   3. The reported `up_acked` matches the upstream byte count the
///      server forwarded across A's lifetime — exactly 4 bytes
///      (`"ping"`); the VLESS request header is parsed by the
///      dispatcher before the upstream socket opens, and only the
///      payload portion that follows it counts toward `up_acked`.
///
/// Uses the higher-level `vless_tcp_pair_from_ws` constructor so
/// the test exercises the public reader API the orchestrator
/// itself uses.
#[tokio::test]
async fn cross_repo_vless_tcp_ws_h2_ack_prefix_reports_up_acked_offset() -> Result<()> {
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

    let (listen_addr, server) =
        setup_vless_ws_server_with_resumption("/vless").await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("ws://{listen_addr}/vless"))?;

    // ── Client A: legacy dial (no Ack-Prefix), one round-trip,
    //              graceful Close so the upstream parks ─────────
    let mut stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-vless-ws-ack-prefix-a",
        None,
        false,
    )
    .await?;
    assert!(
        !stream_a.ack_prefix_advertised_by_server(),
        "client A did not advertise → server must not echo",
    );
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;

    // Drive the round-trip via the raw VLESS handshake — same shape
    // the existing resume test uses for the warm-up half. Switching
    // to the higher-level `vless_tcp_pair_from_ws` here would mean
    // splitting the stream and reassembling, which complicates the
    // graceful Close that `tokio_tungstenite` exposes only on the
    // raw `TransportStream`. The post-resume client B is where the
    // higher-level reader earns its keep.
    let mut handshake_a = Vec::new();
    handshake_a.push(VERSION);
    handshake_a.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_a.push(0);
    handshake_a.push(crate::protocol::vless::COMMAND_TCP);
    handshake_a.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_a.push(0x01);
    handshake_a.extend_from_slice(&[127, 0, 0, 1]);
    handshake_a.extend_from_slice(b"ping");
    stream_a.send(Message::Binary(Bytes::from(handshake_a))).await?;
    let received_a = read_binary_until_at_least(&mut stream_a, 6).await?;
    assert_eq!(&received_a[..2], &[VERSION, 0x00]);
    assert_eq!(&received_a[2..6], b"pong");

    let _ = stream_a.send(Message::Close(None)).await;
    let _ = stream_a.close().await;
    drop(stream_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: resume + Ack-Prefix advertise ────────────────
    let stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-vless-ws-ack-prefix-b",
        Some(token),
        true,
    )
    .await?;
    assert!(
        stream_b.ack_prefix_advertised_by_server(),
        "server must echo X-Outline-Resume-Ack-Prefix: 1 on a vless resume hit \
         when the client advertised the capability",
    );

    // Wrap the resumed stream in the higher-level VLESS pair so we
    // can drive the v1.1 fast path: `consume_ack_prefix_with_timeout`
    // surfaces the offset BEFORE any real payload is read.
    let lifetime_b =
        UpstreamTransportGuard::new("cross-repo-vless-ws-ack-prefix-b", "vless-ws-h2");
    let target_b = TargetAddr::IpV4(Ipv4Addr::LOCALHOST, upstream_addr.port());
    let diag_b = outline_transport::WsReadDiag::default();
    let uuid_b = parse_uuid(TEST_UUID)?;
    let (mut writer_b, mut reader_b) = vless_tcp_pair_from_ws(
        stream_b,
        &uuid_b,
        &target_b,
        Arc::clone(&lifetime_b),
        diag_b,
        None,
    );
    reader_b = reader_b.with_expect_ack_prefix(true);

    // Fire the second payload first so the server has something to
    // emit downstream (the SS test serialised this; VLESS framing
    // inserts the request header on the first send_chunk).
    writer_b.send_chunk(b"helo").await?;

    // Pre-read the offset BEFORE any data read. v1.1 contract: the
    // call returns Some(4) without blocking on real downlink data.
    let offset = reader_b
        .consume_ack_prefix_with_timeout(Duration::from_secs(5))
        .await?;
    assert_eq!(
        offset,
        Some(4),
        "vless Ack-Prefix offset must equal upstream byte count from client A's \"ping\"",
    );
    assert_eq!(reader_b.upstream_acked_offset(), Some(4));

    // The next read_chunk returns the real downlink payload.
    let reply_b = reader_b.read_chunk().await?;
    assert_eq!(reply_b, b"ackk", "vless ss tcp echo via resumed upstream");

    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

    drop(reader_b);
    drop(writer_b);
    drop(lifetime_b);
    server.abort();
    Ok(())
}

/// Variant of [`setup_vless_raw_quic_server`] with a real
/// [`OrphanRegistry`]. Resume tokens for raw QUIC ride inside the
/// VLESS request header's Addons block (tags `0x10 RESUME_CAPABLE`
/// / `0x11 RESUME_ID`); the server still parks the upstream the
/// same way the WS path does once the QUIC bidi stream closes.
async fn setup_vless_raw_quic_server_with_resumption()
-> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    super::cross_repo_install_test_tls_root_on_client();
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let tls_config = super::cross_repo_test_server_tls_config(&[b"vless-mtu", b"vless"]);
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
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(TEST_UUID.into(), Arc::from("test"), None)?;
    let raw_vless_users: Arc<[VlessUser]> = Arc::from(vec![vless_user.clone()].into_boxed_slice());
    let raw_vless_candidates: Arc<[Arc<str>]> =
        Arc::from(vec![vless_user.label_arc()].into_boxed_slice());

    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: Arc::new(BTreeMap::new()),
        xhttp_vless: Arc::new(BTreeMap::new()),
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
            Arc::from(vec![H3Alpn::Vless].into_boxed_slice()),
            raw_vless_users,
            raw_vless_candidates,
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            None,
            ShutdownSignal::never(),
        )
        .await
    });
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_vless_tcp_raw_quic_resume_reattaches_parked_upstream() -> Result<()> {
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

    let (listen_addr, server) = setup_vless_raw_quic_server_with_resumption().await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("https://localhost:{}/", listen_addr.port()))?;
    let uuid_bytes: [u8; 16] = parse_uuid(TEST_UUID)?
        .try_into()
        .expect("UUID parses to 16 bytes");
    let target = TargetAddr::IpV4(Ipv4Addr::LOCALHOST, upstream_addr.port());
    let lifetime_a = UpstreamTransportGuard::new("cross-repo-vless-quic-resume-a", "vless");

    // ── Client A: capability advertise via Addons, first round-trip ──
    let (mut writer_a, mut reader_a, id_rx_a) = connect_vless_tcp_quic_with_resume(
        &cache,
        &url,
        None,
        false,
        "cross-repo-vless-quic-resume-a",
        &uuid_bytes,
        &target,
        Arc::clone(&lifetime_a),
        None,
    )
    .await?;

    writer_a.send_chunk(b"ping").await?;
    let reply_a = reader_a.read_chunk().await?;
    assert_eq!(&reply_a, b"pong");

    // Token surfaces on the first read_chunk via the oneshot
    // receiver returned by the dial — drain it now.
    let token = id_rx_a
        .await
        .map_err(|_| anyhow::anyhow!("resume token sender dropped"))?
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;
    let token_bytes = *token.as_bytes();

    // Drop client A's halves — the QUIC bidi stream closes,
    // server's relay parks the upstream into the orphan registry.
    drop(reader_a);
    drop(writer_a);
    drop(lifetime_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: dials with `RESUME_ID` Addons opcode set ──
    let lifetime_b = UpstreamTransportGuard::new("cross-repo-vless-quic-resume-b", "vless");
    let (mut writer_b, mut reader_b, _id_rx_b) = connect_vless_tcp_quic_with_resume(
        &cache,
        &url,
        None,
        false,
        "cross-repo-vless-quic-resume-b",
        &uuid_bytes,
        // Target is irrelevant on the resume path — server uses
        // the parked upstream — but the VLESS parser still wants
        // a valid one in the request header.
        &target,
        Arc::clone(&lifetime_b),
        Some(&token_bytes),
    )
    .await?;

    writer_b.send_chunk(b"helo").await?;
    let reply_b = reader_b.read_chunk().await?;
    assert_eq!(&reply_b, b"ackk", "echo via resumed upstream");

    let (first, second) =
        tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(&first, b"ping");
    assert_eq!(&second, b"helo");

    drop(reader_b);
    drop(writer_b);
    drop(lifetime_b);
    server.abort();
    Ok(())
}

/// Same as [`setup_vless_ws_h3_server`] but with `OrphanRegistry`
/// enabled. RFC 9220 (WebSocket-over-HTTP/3 CONNECT extended)
/// honours the same `X-Outline-Resume-Capable` /
/// `X-Outline-Session` header pair the h2 path uses.
async fn setup_vless_ws_h3_server_with_resumption(
    ws_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
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
    let vless_routes = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: vless_user,
        ws_path: Arc::from(ws_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
        xhttp_vless: Arc::new(BTreeMap::new()),
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
            None,
            ShutdownSignal::never(),
        )
        .await
    });
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_vless_tcp_ws_h3_resume_reattaches_parked_upstream() -> Result<()> {
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

    let (listen_addr, server) = setup_vless_ws_h3_server_with_resumption("/vless").await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("wss://localhost:{}/vless", listen_addr.port()))?;

    // ── Client A: capability advertise + first round-trip ──────
    let mut stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH3,
        None,
        false,
        "cross-repo-vless-ws-h3-resume-a",
        None,
        false,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;

    let mut handshake_a = Vec::new();
    handshake_a.push(VERSION);
    handshake_a.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_a.push(0);
    handshake_a.push(crate::protocol::vless::COMMAND_TCP);
    handshake_a.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_a.push(0x01);
    handshake_a.extend_from_slice(&[127, 0, 0, 1]);
    handshake_a.extend_from_slice(b"ping");
    stream_a
        .send(Message::Binary(Bytes::from(handshake_a)))
        .await?;
    let received_a = read_binary_until_at_least(&mut stream_a, 6).await?;
    assert_eq!(&received_a[..2], &[VERSION, 0x00]);
    assert_eq!(&received_a[2..6], b"pong");

    // Send a graceful Close so the server's WS reader sees a clean
    // shutdown and the relay's park-on-disconnect path stashes the
    // upstream into the orphan registry. Without it the QUIC bidi
    // stream would close abruptly and the relay would tear the
    // upstream down.
    use futures_util::SinkExt;
    let _ = stream_a.send(Message::Close(None)).await;
    let _ = stream_a.close().await;
    drop(stream_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: dials with the same token, expects reattach ──
    let mut stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH3,
        None,
        false,
        "cross-repo-vless-ws-h3-resume-b",
        Some(token),
        false,
    )
    .await?;
    let _issued_b = stream_b.issued_session_id();

    let mut handshake_b = Vec::new();
    handshake_b.push(VERSION);
    handshake_b.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_b.push(0);
    handshake_b.push(crate::protocol::vless::COMMAND_TCP);
    handshake_b.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_b.push(0x01);
    handshake_b.extend_from_slice(&[127, 0, 0, 1]);
    handshake_b.extend_from_slice(b"helo");
    stream_b
        .send(Message::Binary(Bytes::from(handshake_b)))
        .await?;
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

/// Spins up an axum-over-TLS server (no h3 / no QUIC listener) with
/// the VLESS WS route and a real `OrphanRegistry`. The dispatcher
/// fallback path is exercised by pointing client B at the same
/// `wss://` URL while no UDP listener exists — the WS-h3 dial
/// times out after 10 s, then `connect_websocket_h2` reattaches
/// via TLS+TCP carrying the same `X-Outline-Resume` token.
async fn setup_vless_ws_h2_tls_server_with_resumption(
    ws_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    super::cross_repo_install_test_tls_root_on_client();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(TEST_UUID.into(), Arc::from("test"), None)?;
    let vless_routes = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: vless_user,
        ws_path: Arc::from(ws_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
        xhttp_vless: Arc::new(BTreeMap::new()),
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
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth, None);

    let server_tls = super::cross_repo_test_server_tls_config(&[b"h2", b"http/1.1"]);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));

    let handle = tokio::spawn(super::cross_repo_serve_axum_with_tls(listener, app, acceptor));
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_vless_tcp_ws_h3_to_h2_fallback_with_resume_token() -> Result<()> {
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

    let (listen_addr, server) =
        setup_vless_ws_h2_tls_server_with_resumption("/vless").await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("wss://localhost:{}/vless", listen_addr.port()))?;

    // ── Client A: WsH2 over TLS — gets the resume token ────────
    let mut stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-vless-fallback-a",
        None,
        false,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;

    let mut handshake_a = Vec::new();
    handshake_a.push(VERSION);
    handshake_a.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_a.push(0);
    handshake_a.push(crate::protocol::vless::COMMAND_TCP);
    handshake_a.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_a.push(0x01);
    handshake_a.extend_from_slice(&[127, 0, 0, 1]);
    handshake_a.extend_from_slice(b"ping");
    stream_a
        .send(Message::Binary(Bytes::from(handshake_a)))
        .await?;
    let received_a = read_binary_until_at_least(&mut stream_a, 6).await?;
    assert_eq!(&received_a[..2], &[VERSION, 0x00]);
    assert_eq!(&received_a[2..6], b"pong");

    use futures_util::SinkExt as _;
    let _ = stream_a.send(Message::Close(None)).await;
    let _ = stream_a.close().await;
    drop(stream_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: WsH3 → 10 s timeout → fallback to WsH2 ───────
    let mut stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH3,
        None,
        false,
        "cross-repo-vless-fallback-b",
        Some(token),
        false,
    )
    .await?;
    assert_eq!(
        stream_b.downgraded_from(),
        Some(TransportMode::WsH3),
        "client B should report a downgrade from WsH3",
    );
    let _issued_b = stream_b.issued_session_id();

    let mut handshake_b = Vec::new();
    handshake_b.push(VERSION);
    handshake_b.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_b.push(0);
    handshake_b.push(crate::protocol::vless::COMMAND_TCP);
    handshake_b.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_b.push(0x01);
    handshake_b.extend_from_slice(&[127, 0, 0, 1]);
    handshake_b.extend_from_slice(b"helo");
    stream_b
        .send(Message::Binary(Bytes::from(handshake_b)))
        .await?;
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

/// Plain-TCP, h1-only axum server with `OrphanRegistry` enabled.
/// Drives the dispatcher's WS-h2 → WS-h1 fallback path: a WsH2 dial
/// hits this listener with the h2 preface, hyper's h1 codec rejects
/// the malformed request, the client records the failure and retries
/// on h1 with the same `X-Outline-Resume` header. No TLS — the h1
/// path goes through tungstenite's own `client_async_tls`, which
/// uses webpki and does not consult the cross-repo TLS override
/// slot, so a TLS dial would fail at certificate validation. Plain
/// TCP keeps the test focused on the dispatcher's downgrade logic.
async fn setup_vless_ws_h1_only_server_with_resumption(
    ws_path: &'static str,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new(TEST_UUID.into(), Arc::from("test"), None)?;
    let vless_routes = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: vless_user,
        ws_path: Arc::from(ws_path),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
        xhttp_vless: Arc::new(BTreeMap::new()),
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
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth, None);

    let handle = tokio::spawn(super::cross_repo_serve_axum_h1_only(listener, app));
    Ok((listen_addr, handle))
}

#[tokio::test]
async fn cross_repo_vless_tcp_ws_h2_to_h1_fallback_with_resume_token() -> Result<()> {
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

    let (listen_addr, server) =
        setup_vless_ws_h1_only_server_with_resumption("/vless").await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let url = Url::parse(&format!("ws://{listen_addr}/vless"))?;

    // ── Client A: WsH1 over plain TCP — gets the resume token ──
    let mut stream_a = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH1,
        None,
        false,
        "cross-repo-vless-h2-h1-fallback-a",
        None,
        false,
    )
    .await?;
    let token = stream_a
        .issued_session_id()
        .ok_or_else(|| anyhow::anyhow!("client A: server did not surface a resume token"))?;

    let mut handshake_a = Vec::new();
    handshake_a.push(VERSION);
    handshake_a.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_a.push(0);
    handshake_a.push(crate::protocol::vless::COMMAND_TCP);
    handshake_a.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_a.push(0x01);
    handshake_a.extend_from_slice(&[127, 0, 0, 1]);
    handshake_a.extend_from_slice(b"ping");
    stream_a
        .send(Message::Binary(Bytes::from(handshake_a)))
        .await?;
    let received_a = read_binary_until_at_least(&mut stream_a, 6).await?;
    assert_eq!(&received_a[..2], &[VERSION, 0x00]);
    assert_eq!(&received_a[2..6], b"pong");

    let _ = stream_a.send(Message::Close(None)).await;
    let _ = stream_a.close().await;
    drop(stream_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Client B: WsH2 → h2 handshake fails → fallback to WsH1 ─
    let mut stream_b = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::WsH2,
        None,
        false,
        "cross-repo-vless-h2-h1-fallback-b",
        Some(token),
        false,
    )
    .await?;
    assert_eq!(
        stream_b.downgraded_from(),
        Some(TransportMode::WsH2),
        "client B should report a downgrade from WsH2",
    );
    let _issued_b = stream_b.issued_session_id();

    let mut handshake_b = Vec::new();
    handshake_b.push(VERSION);
    handshake_b.extend_from_slice(&parse_uuid(TEST_UUID)?);
    handshake_b.push(0);
    handshake_b.push(crate::protocol::vless::COMMAND_TCP);
    handshake_b.extend_from_slice(&upstream_addr.port().to_be_bytes());
    handshake_b.push(0x01);
    handshake_b.extend_from_slice(&[127, 0, 0, 1]);
    handshake_b.extend_from_slice(b"helo");
    stream_b
        .send(Message::Binary(Bytes::from(handshake_b)))
        .await?;
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
