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
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::resumption::{OrphanRegistry, ResumptionConfig};
use super::super::setup::{VlessUserRoute, build_vless_transport_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, Services, UdpServices, UserKeySlice};
use super::super::{DnsCache, build_app, serve_h3_server};
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
    let app = build_app(routes, services, auth);
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
    let app = build_app(routes, services, auth);
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
