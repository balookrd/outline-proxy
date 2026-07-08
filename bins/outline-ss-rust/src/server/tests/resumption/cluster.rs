//! End-to-end tests for the mesh cluster (phase 8).
//!
//! Each test boots a small in-process cluster of real `outline-ss-rust` nodes,
//! each with `[cluster]` wired (a PSK-derived mesh endpoint + peer pool) and
//! session resumption enabled, then drives an SS-over-WebSocket client through
//! the edge relay and asserts the end-to-end behaviour on the wire.
//!
//! The nodes share one PSK, so every node derives the same shard-obfuscation
//! key (a resume id minted by one decodes to the same shard on all) and the
//! same mesh mutual-auth pin. All nodes use `sample_config`, so the SS user
//! ("bob") and its key are identical across nodes — the client encrypts once
//! and whichever home decrypts it succeeds.
//!
//! The load-bearing probe is the echo target's accept counter (see
//! [`super::spawn_echo_target`]): a fresh upstream connect bumps it, a resume
//! hit reuses the parked socket and leaves it unchanged.

use std::{
    collections::{BTreeMap, HashMap},
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use axum::http::{Method, Request, StatusCode, Version, header};
use futures_util::{SinkExt, StreamExt};
use h3::ext::Protocol as H3Protocol;
use outline_transport::{
    DnsCache as ClientDnsCache, SessionId as ClientSessionId, TcpShadowsocksReader,
    TcpShadowsocksWriter, TransportMode, UdpWsTransport, UpstreamTransportGuard,
};
use outline_wire::cluster::{ObfuscationKey, ShardId};
use quinn::Endpoint;
use ring::rand::SystemRandom;
use rustls::pki_types::CertificateDer;
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, Message as H3Message, Role as H3Role,
    Stream as H3Stream, WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use url::Url;

use super::super::super::bootstrap::serve_listener;
use super::super::super::cluster::ClusterCtx;
use super::super::super::nat::NatTable;
use super::super::super::replay::ReplayStore;
use super::super::super::resumption::{OrphanRegistry, ResumptionConfig, SessionId};
use super::super::super::setup::{
    SsXhttpUserRoute, VlessUserRoute, build_vless_transport_route_map, build_xhttp_ss_route_map,
};
use super::super::super::shutdown::ShutdownSignal;
use super::super::super::state::{RoutesSnapshot, UserKeySlice};
use super::super::super::transport::mesh_relay::run_mesh_listener;
use super::super::super::{
    AuthPolicy, DnsCache, H3ServeCtx, RouteRegistry, Services, UdpServices, build_app,
    build_transport_route_map, build_user_routes, ensure_rustls_provider_installed,
    serve_h3_server, user_keys,
};
use super::super::{
    connect_websocket_with_resume, sample_config, test_h3_client_config, test_h3_server_tls,
};
use super::ss::ss_handshake_frame;
use super::vless::vless_udp_request;
use super::{connect_ws_h1, expect_binary_reply, spawn_echo_target, spawn_echo_udp_target};
use crate::config::{CipherKind, ClusterConfig, ClusterPsk, H3Alpn};
use crate::crypto::{AeadStreamDecryptor, UserKey, decrypt_udp_packet, encrypt_udp_packet};
use crate::metrics::{Metrics, Transport};
use crate::protocol::TargetAddr;
use crate::protocol::vless::{VERSION as VLESS_VERSION, VlessUser};

/// Fixed VLESS user UUID registered on every cluster node's `/vless` route, so
/// the VLESS(-UDP) e2e shares one identity across nodes (mirrors the shared SS
/// user "bob").
const CLUSTER_VLESS_UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

/// A running cluster node: an SS-over-WS listener plus a mesh endpoint (home
/// listener + edge dialer). Aborts its tasks on drop so tests don't leak
/// listeners between cases.
struct ClusterNode {
    listen_addr: SocketAddr,
    mesh_addr: SocketAddr,
    ws_task: JoinHandle<Result<()>>,
    mesh_task: JoinHandle<Result<()>>,
}

impl Drop for ClusterNode {
    fn drop(&mut self) {
        self.ws_task.abort();
        self.mesh_task.abort();
    }
}

/// The shared pieces of a cluster node: routing/services/auth wired to a
/// cluster-aware resumption registry, plus the built mesh runtime. Both the WS
/// and the h3 node spawns build these, then bind their own carrier listener.
struct ClusterParts {
    routes: RoutesSnapshot,
    services: Arc<Services>,
    auth: Arc<AuthPolicy>,
    cluster: Arc<ClusterCtx>,
    mesh_addr: SocketAddr,
    user: UserKey,
}

/// Builds the cluster-aware services + mesh runtime for one node. Carrier-
/// agnostic: the caller binds the WS or h3 listener over these. When
/// `xhttp_ss_path` is set, the node also serves (edge) / resolves (home) an
/// SS-over-XHTTP base path for the shared user.
fn build_cluster_parts(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    xhttp_ss_path: Option<&str>,
    xhttp_ss_udp_path: Option<&str>,
) -> Result<ClusterParts> {
    // The mesh QUIC endpoint needs the process-wide rustls provider installed.
    ensure_rustls_provider_installed();

    let mut config = sample_config((Ipv4Addr::LOCALHOST, 0).into());
    config.session_resumption.enabled = true;
    let user_routes = build_user_routes(&config)?;
    let user = user_routes[0].user.clone();
    let users = user_keys(user_routes.as_ref());

    let metrics = Metrics::new(&config);
    let shard = ShardId::new(shard).unwrap();
    let obf_key = ObfuscationKey::derive_from_psk(psk);
    let orphan_registry = Arc::new(
        OrphanRegistry::new(
            ResumptionConfig::from(&config.session_resumption),
            Arc::clone(&metrics),
        )
        .with_cluster(obf_key, shard),
    );

    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));
    let tcp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Udp));
    // Registers a single SS-over-XHTTP base path for the shared user, or an
    // empty table when the path is unset. Used for both the TCP (`xhttp_ss`) and
    // UDP (`xhttp_ss_udp`) route tables.
    let build_ss_xhttp = |path: Option<&str>| match path {
        Some(p) => Arc::new(build_xhttp_ss_route_map(&[SsXhttpUserRoute {
            user: user_routes[0].user.clone(),
            xhttp_path: Arc::from(p),
        }])),
        None => Arc::new(BTreeMap::new()),
    };
    let xhttp_ss = build_ss_xhttp(xhttp_ss_path);
    let xhttp_ss_udp = build_ss_xhttp(xhttp_ss_udp_path);
    // A fixed VLESS user on `/vless`, shared across nodes (like the SS user), so
    // the VLESS(-UDP) cluster e2e can encrypt once and any home authenticates
    // it. SS-only tests never hit `/vless`, so this is harmless to them.
    let vless = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: VlessUser::new(CLUSTER_VLESS_UUID.into(), Arc::from("cluster-vless"), None, None)?,
        ws_path: Arc::from("/vless"),
    }]));
    let routes: RoutesSnapshot = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: tcp_routes,
        udp: udp_routes,
        vless,
        xhttp_vless: Arc::new(BTreeMap::new()),
        xhttp_ss,
        xhttp_ss_udp,
    }));
    let services = Arc::new(Services::new(
        Arc::clone(&metrics),
        dns_cache,
        false,
        None,
        UdpServices {
            nat_table,
            replay_store: ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        Some(orphan_registry),
        16,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
    });

    let cluster_cfg = ClusterConfig {
        shard,
        psk: ClusterPsk::from_bytes(psk.to_vec()),
        mesh_listen: (Ipv4Addr::LOCALHOST, 0).into(),
        mesh_relay_budget: budget,
        peers,
    };
    let cluster = ClusterCtx::build(&cluster_cfg)?;
    let mesh_addr = cluster.endpoint.local_addr()?;

    Ok(ClusterParts {
        routes,
        services,
        auth,
        cluster,
        mesh_addr,
        user,
    })
}

/// Boots one WS cluster node on fresh random localhost ports: an SS-over-WS
/// listener and a mesh endpoint (home listener + edge dialer). Returns the node
/// and the shared SS `UserKey` clients encrypt with.
async fn spawn_cluster_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    xhttp_ss_path: Option<&str>,
    xhttp_ss_udp_path: Option<&str>,
) -> Result<(ClusterNode, UserKey)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let ClusterParts {
        routes,
        services,
        auth,
        cluster,
        mesh_addr,
        user,
    } = build_cluster_parts(psk, shard, peers, budget, xhttp_ss_path, xhttp_ss_udp_path)?;

    let app = build_app(
        Arc::clone(&routes),
        Arc::clone(&services),
        auth,
        None,
        Some(Arc::clone(&cluster)),
    );
    let ws_task =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });
    let mesh_task =
        tokio::spawn(run_mesh_listener(cluster, services, routes, ShutdownSignal::never()));

    Ok((
        ClusterNode {
            listen_addr,
            mesh_addr,
            ws_task,
            mesh_task,
        },
        user,
    ))
}

/// A running h3 edge node: an HTTP/3 WebSocket server that relays to peer homes.
/// Aborts its task on drop.
struct H3EdgeNode {
    addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    h3_task: JoinHandle<Result<()>>,
}

impl Drop for H3EdgeNode {
    fn drop(&mut self) {
        self.h3_task.abort();
    }
}

/// Boots an h3 edge node: a real `serve_h3_server` with the cluster wired, so
/// its CONNECT accept path relays a foreign-shard resume to the home. The edge
/// only dials the mesh (its `ClusterCtx` endpoint), so no mesh listener runs.
async fn spawn_h3_edge_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
) -> Result<(H3EdgeNode, UserKey)> {
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let server = H3WebSocketServer::<H3Transport>::bind(
        (Ipv4Addr::LOCALHOST, 0).into(),
        tls_config,
        H3WsConfig::default(),
    )
    .await?;
    let addr = server.local_addr()?;

    let ClusterParts {
        routes, services, auth, cluster, user, ..
    } = build_cluster_parts(psk, shard, peers, budget, None, None)?;
    let ctx = H3ServeCtx {
        routes,
        services,
        auth,
        alpn: Arc::from(vec![H3Alpn::H3].into_boxed_slice()),
        http_fallback: None,
        cluster: Some(cluster),
    };
    let h3_task = tokio::spawn(serve_h3_server(server, ctx, ShutdownSignal::never()));

    Ok((H3EdgeNode { addr, cert_der, h3_task }, user))
}

/// Fabricates a resume id whose shard decodes to `shard` under `psk` — as if a
/// home on that shard had minted it on a prior connect.
fn resume_id_for_shard(psk: &[u8], shard: u8) -> Result<SessionId> {
    let key = ObfuscationKey::derive_from_psk(psk);
    Ok(SessionId::random_with_shard(
        &SystemRandom::new(),
        &key,
        ShardId::new(shard).unwrap(),
    )?)
}

/// A TCP target that accepts connections and then never reads from them, so a
/// writer's socket buffer fills and its writes block — used to stall the home's
/// upstream and, by backpressure, the whole relay.
async fn spawn_blackhole_target() -> Result<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        // Keep every accepted stream alive (never dropped, never read) so it
        // stays open and un-drained for the lifetime of the test.
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    Ok(addr)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Survival across an edge switch: a session established through one edge is
/// resumed through a *different* edge, both relaying to the same home over the
/// mesh. The home reuses the parked upstream, so the echo target sees exactly
/// one accept across the two connects.
#[tokio::test]
async fn cluster_session_survives_edge_switch() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-survival-psk";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    // Home owns shard 1; two edges (shards 2, 3) relay to it.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge_a, _) =
        spawn_cluster_node(PSK, 2, peers.clone(), Duration::from_secs(4), None, None).await?;
    let (edge_b, _) = spawn_cluster_node(PSK, 3, peers, Duration::from_secs(4), None, None).await?;

    // The client holds a home-shard resume id (as if the home minted it on a
    // prior connect). Both edges route it to the home over the mesh.
    let session_id = resume_id_for_shard(PSK, 1)?;

    // Session #1 via edge A: the home misses (never parked) → fresh upstream,
    // then parks on close under the id the client presented.
    let (mut sock_a, _) = connect_ws_h1(edge_a.listen_addr, "/tcp", Some(session_id), true).await?;
    sock_a
        .send(WsMessage::Binary(ss_handshake_frame(&user, echo_addr, b"via-edge-a")?))
        .await?;
    let _ = expect_binary_reply(&mut sock_a).await?;
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "first relay must open exactly one upstream"
    );
    sock_a.close(None).await?;
    drop(sock_a);
    // Let the mesh stream finish and the home park the upstream on the FIN.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Session #2 via edge B, same id: the home's take_for_resume hits → the
    // parked upstream is reattached, with no fresh connect.
    let (mut sock_b, _) = connect_ws_h1(edge_b.listen_addr, "/tcp", Some(session_id), true).await?;
    sock_b
        .send(WsMessage::Binary(ss_handshake_frame(&user, echo_addr, b"via-edge-b")?))
        .await?;
    let _ = expect_binary_reply(&mut sock_b).await?;
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "resume across the edge switch must reuse the parked upstream (no fresh connect)"
    );
    sock_b.close(None).await?;
    Ok(())
}

/// A large payload survives the relay byte-for-byte in both directions. 512 KiB
/// forces several 256 KiB mesh read chunks each way, exercising the
/// chunk-boundary reassembly that is the relay's main silent-corruption risk.
#[tokio::test]
async fn cluster_relay_preserves_large_payload() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-integrity-psk";
    let (echo_addr, _accepts) = spawn_echo_target().await?;
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;

    // Deterministic 512 KiB pattern.
    let payload: Vec<u8> = (0..512 * 1024usize)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect();

    let (socket, _) = connect_ws_h1(edge.listen_addr, "/tcp", Some(session_id), true).await?;
    let frame = ss_handshake_frame(&user, echo_addr, &payload)?;

    // Send and receive concurrently so the round-trip can't deadlock on
    // buffer capacity while the client is still writing the uplink.
    let (mut sink, mut stream) = socket.split();
    let send_task = tokio::spawn(async move { sink.send(WsMessage::Binary(frame)).await });

    let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user.clone()].into_boxed_slice()));
    let mut plaintext = Vec::new();
    while plaintext.len() < payload.len() {
        let next = tokio::time::timeout(Duration::from_secs(10), stream.next()).await?;
        match next {
            Some(Ok(WsMessage::Binary(bytes))) => {
                decryptor.feed_ciphertext(&bytes);
                decryptor.drain_plaintext(&mut plaintext)?;
            },
            Some(Ok(WsMessage::Close(_))) | None => break,
            // Ignore any control frames the carrier may surface.
            Some(Ok(_)) => {},
            Some(Err(error)) => bail!("edge websocket error: {error}"),
        }
    }
    let _ = send_task.await?;

    assert_eq!(plaintext.len(), payload.len(), "relayed byte count differs from what was sent");
    assert!(
        plaintext == payload,
        "relayed payload was corrupted or reordered across the mesh"
    );
    Ok(())
}

/// When the edge has no mesh route to the resume id's home shard, `open_relay`
/// fails and the edge must degrade to a fresh local session rather than drop
/// the client. The echo target sees a fresh upstream connect.
#[tokio::test]
async fn cluster_unreachable_home_falls_back_to_local_session() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-fallback-psk";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    // An edge on shard 2 with NO peer for shard 1: a shard-1 resume relays
    // nowhere, so the edge serves the carrier locally.
    let (edge, user) =
        spawn_cluster_node(PSK, 2, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let foreign_id = resume_id_for_shard(PSK, 1)?;

    let (mut sock, _) = connect_ws_h1(edge.listen_addr, "/tcp", Some(foreign_id), true).await?;
    sock.send(WsMessage::Binary(ss_handshake_frame(&user, echo_addr, b"fallback")?))
        .await?;
    let _ = expect_binary_reply(&mut sock).await?;
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "an unreachable home must degrade to a fresh local upstream, not drop the client"
    );
    sock.close(None).await?;
    Ok(())
}

/// A relay that stops making progress is torn down on the edge's health budget
/// rather than hanging forever. The home's upstream is a black hole that never
/// drains, so a large uplink backs up through the home into the mesh window;
/// the edge's uplink write stalls past the short budget and it resets the
/// carrier, closing the client.
#[tokio::test]
async fn cluster_stalled_relay_tears_down_on_health_budget() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-budget-psk";
    let blackhole = spawn_blackhole_target().await?;

    // Home with a generous budget; edge with a short one so the stall trips fast.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(30), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) =
        spawn_cluster_node(PSK, 2, peers, Duration::from_millis(300), None, None).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;

    // Large enough to overflow the target socket buffer, the home's read buffer
    // and the mesh QUIC send window, so the edge's uplink write genuinely
    // blocks (not just buffers) and the budget can fire.
    let payload = vec![0xABu8; 8 * 1024 * 1024];

    let (socket, _) = connect_ws_h1(edge.listen_addr, "/tcp", Some(session_id), true).await?;
    let frame = ss_handshake_frame(&user, blackhole, &payload)?;
    let (mut sink, mut stream) = socket.split();
    // The send may never fully flush before the teardown — that's the point.
    let _send_task = tokio::spawn(async move {
        let _ = sink.send(WsMessage::Binary(frame)).await;
    });

    // The stalled carrier must close within a small multiple of the budget
    // instead of hanging. A Close frame, a clean EOF, or a reset error all
    // count as a teardown.
    let torn_down = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match stream.next().await {
                Some(Ok(WsMessage::Close(_))) | None | Some(Err(_)) => break,
                // Ignore any bytes the home echoed before the stall.
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        torn_down.is_ok(),
        "a stalled relay must be torn down on the health budget, not hang"
    );
    Ok(())
}

/// The edge relay works over the HTTP/3 carrier too: an h3 client connects to
/// an h3 edge, presents a home-shard resume id, and the edge splices the h3
/// WebSocket to the mesh so the home serves it. A binary reply back through the
/// relay proves the h3 accept-branch wiring end to end (a different `WsSocket`
/// impl than the h1/h2 path).
#[tokio::test]
async fn cluster_h3_edge_relays_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-h3-psk";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    // Home: a plain-WS node with the mesh listener — carrier-agnostic on the
    // home side, so it serves an h3-originated relay just like a WS one.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_h3_edge_node(PSK, 2, peers, Duration::from_secs(4)).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;

    // h3 client → edge, presenting the home-shard resume id.
    let mut endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(test_h3_client_config(edge.cert_der.clone())?);
    let connection = endpoint.connect(edge.addr, "localhost")?.await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver_task =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost:{}/tcp", edge.addr.port()))
        .version(Version::HTTP_3)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header("x-outline-resume-capable", "1")
        .header("x-outline-resume", session_id.to_hex())
        .extension(H3Protocol::WEBSOCKET)
        .body(())?;
    let mut req_stream = send_request.send_request(request).await?;
    let response = req_stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK, "h3 CONNECT must succeed on the edge");

    let h3_stream = H3Stream::<H3Transport>::from_h3_client(req_stream);
    let mut socket = H3WebSocketStream::from_raw(h3_stream, H3Role::Client, H3WsConfig::default());

    socket
        .send(H3Message::Binary(ss_handshake_frame(&user, echo_addr, b"via-h3-edge")?))
        .await?;
    let reply = tokio::time::timeout(Duration::from_secs(5), socket.next()).await?;
    match reply {
        Some(Ok(H3Message::Binary(_))) => {},
        other => bail!("expected a binary reply relayed over the h3 edge, got {other:?}"),
    }
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the h3 edge relay must open exactly one upstream on the home"
    );

    driver_task.abort();
    Ok(())
}

/// The SOCKS5 IPv4 address header + payload the server's `parse_target_addr`
/// expects as the first SS chunk right after the salt.
fn ss_first_chunk(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut chunk = vec![0x01]; // ATYP = IPv4
    match target.ip() {
        std::net::IpAddr::V4(v4) => chunk.extend_from_slice(&v4.octets()),
        std::net::IpAddr::V6(_) => unreachable!("test upstream is always ipv4"),
    }
    chunk.extend_from_slice(&target.port().to_be_bytes());
    chunk.extend_from_slice(payload);
    chunk
}

/// The edge relay also works for XHTTP: an SS-over-XHTTP (h2 packet-up) client
/// dials an edge that serves the base path, presents a home-shard resume id,
/// and the edge relays the reassembled byte stream to the home over the mesh.
/// The home resolves the `xhttp_ss` route (the new `SsXhttp` carrier kind) and
/// decrypts the SS stream. A full ping/pong round trip proves the XHTTP
/// reassembly → mesh → home path end to end.
#[tokio::test]
async fn cluster_xhttp_edge_relays_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-xhttp-psk";
    // TCP echo upstream on the home side.
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut got = [0_u8; 4];
        stream.read_exact(&mut got).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(got)
    });

    // Home resolves the `/ssx` xhttp_ss route (for the relayed carrier's user
    // lookup) and runs the mesh listener; the edge serves `/ssx` and relays.
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), Some("/ssx"), None)
            .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) =
        spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), Some("/ssx"), None).await?;

    // Home-shard resume id, presented by the client on the XHTTP dial.
    let session_id = resume_id_for_shard(PSK, 1)?;
    let client_resume = ClientSessionId::from_bytes(*session_id.as_bytes());

    // Real client: SS-over-XHTTP (h2 packet-up) to the edge, resuming the
    // home-shard id so the edge routes the session to the home over the mesh.
    let url = Url::parse(&format!("http://{}/ssx", edge.listen_addr))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let stream = connect_websocket_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        None,
        false,
        "cluster-xhttp-test",
        Some(client_resume),
        false,
        false,
        0,
    )
    .await?;

    // Layer the SS AEAD stream on the XHTTP carrier, as the real client does.
    // The shared user is `sample_config`'s bob (secret-b / Chacha20).
    let master_key = CipherKind::Chacha20IetfPoly1305.derive_master_key("secret-b")?;
    let lifetime = UpstreamTransportGuard::new("cluster-xhttp-test", "tcp");
    let (sink, source) = stream.split();
    let (mut writer, ctrl_tx) = TcpShadowsocksWriter::connect(
        sink,
        CipherKind::Chacha20IetfPoly1305,
        &master_key,
        Arc::clone(&lifetime),
    )
    .await?;
    let request_salt = writer.request_salt();
    let mut reader = TcpShadowsocksReader::new(
        source,
        CipherKind::Chacha20IetfPoly1305,
        &master_key,
        lifetime,
        ctrl_tx,
    )
    .with_request_salt(request_salt);

    writer.send_chunk(&ss_first_chunk(upstream_addr, b"ping")).await?;

    let mut echoed = Vec::new();
    while echoed.len() < 4 {
        let chunk = reader.read_chunk().await?;
        if chunk.is_empty() {
            break;
        }
        echoed.extend_from_slice(&chunk);
    }
    assert_eq!(&echoed[..4], b"pong", "SS-over-XHTTP echo relayed home→edge→client");

    let upstream_bytes = tokio::time::timeout(Duration::from_secs(5), upstream_task).await???;
    assert_eq!(
        &upstream_bytes, b"ping",
        "uplink reached the home's upstream via the mesh relay"
    );

    drop(writer);
    drop(reader);
    Ok(())
}

/// SS-UDP datagrams relay through the mesh byte-for-byte. Each client packet is
/// one atomic AEAD datagram; the edge length-frames it onto the mesh stream and
/// the home de-frames it, decrypts, forwards to the target and relays the echo
/// back. Distinct sizes (incl. a 1200-byte packet) exercise the datagram
/// framing that is the SS-UDP relay's main silent-corruption risk — a byte
/// splice would coalesce or split packets and break the per-packet AEAD.
#[tokio::test]
async fn cluster_udp_relays_datagrams_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-relay-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Home owns shard 1; an edge (shard 2) relays /udp to it over the mesh.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // A home-shard resume id routes the edge's /udp carrier to the home.
    let session_id = resume_id_for_shard(PSK, 1)?;
    let (mut socket, _) = connect_ws_h1(edge.listen_addr, "/udp", Some(session_id), true).await?;

    // Each distinct datagram size must round-trip byte-exact through the relay.
    for (i, &size) in [4usize, 1200, 64].iter().enumerate() {
        let payload: Vec<u8> = (0..size).map(|b| (b + i) as u8).collect();
        let mut plaintext = TargetAddr::from(target_addr).to_wire_bytes()?;
        plaintext.extend_from_slice(&payload);
        socket
            .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
            .await?;

        let reply = expect_binary_reply(&mut socket).await?;
        let decoded = decrypt_udp_packet(std::slice::from_ref(&user), &reply)?;
        assert!(
            decoded.payload.ends_with(&payload),
            "datagram {i} ({size} bytes) must relay home→edge→client byte-exact",
        );
    }

    socket.close(None).await?;
    Ok(())
}

/// An SS-UDP session survives an edge switch: a datagram sent through one edge
/// and then a *different* edge relay to the same home, which re-points the
/// parked NAT entry at the new relay stream rather than binding a fresh upstream
/// socket — so the target sees exactly one source address. The mesh counterpart
/// of `ss_udp_resume_hit_reattaches_parked_nat_entry`.
#[tokio::test]
async fn cluster_udp_survives_edge_switch() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-switch-psk";
    let (target_addr, sources) = spawn_echo_udp_target().await?;

    // Home owns shard 1; two edges (shards 2, 3) relay to it.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge_a, _) =
        spawn_cluster_node(PSK, 2, peers.clone(), Duration::from_secs(4), None, None).await?;
    let (edge_b, _) = spawn_cluster_node(PSK, 3, peers, Duration::from_secs(4), None, None).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;

    // Session #1 via edge A: the home misses (never parked) → fresh NAT entry,
    // parked on close under the id the client presented.
    let (mut sock_a, _) = connect_ws_h1(edge_a.listen_addr, "/udp", Some(session_id), true).await?;
    let mut plaintext = TargetAddr::from(target_addr).to_wire_bytes()?;
    plaintext.extend_from_slice(b"udp-a");
    sock_a
        .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
        .await?;
    let _ = expect_binary_reply(&mut sock_a).await?;
    assert_eq!(
        sources.lock().await.len(),
        1,
        "first relay must open exactly one upstream source"
    );
    sock_a.close(None).await?;
    drop(sock_a);
    // Let the mesh stream finish and the home park the NAT keys on the FIN.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Session #2 via edge B, same id: the home's `attempt_ss_udp_resume` hits →
    // the parked NAT entry is re-pointed at the new relay, with no fresh bind.
    let (mut sock_b, _) = connect_ws_h1(edge_b.listen_addr, "/udp", Some(session_id), true).await?;
    let mut plaintext = TargetAddr::from(target_addr).to_wire_bytes()?;
    plaintext.extend_from_slice(b"udp-b");
    sock_b
        .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
        .await?;
    let _ = expect_binary_reply(&mut sock_b).await?;
    assert_eq!(
        sources.lock().await.len(),
        1,
        "resume across the edge switch must reuse the parked NAT entry (one upstream source)"
    );
    sock_b.close(None).await?;
    Ok(())
}

/// SS-UDP over XHTTP relays through the mesh. The client drives the real
/// `UdpWsTransport` (packet-up h2) against the edge with a home-shard resume id;
/// the edge relays the datagram carrier to the home with datagram framing
/// (`SsUdpXhttp` → `edge_relay_udp::<XhttpDuplex>`), the home resolves the user
/// on its `xhttp_ss_udp` table and forwards to the target. Proves the XHTTP
/// datagram edge path end to end, byte-exact.
#[tokio::test]
async fn cluster_udp_xhttp_relays_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-xhttp-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Home resolves `/ssu` on its `xhttp_ss_udp` table and runs the mesh
    // listener; the edge serves `/ssu` and relays a foreign-shard resume.
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, Some("/ssu"))
            .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) =
        spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, Some("/ssu")).await?;

    // Home-shard resume id: the edge routes this XHTTP UDP session to the home.
    let session_id = resume_id_for_shard(PSK, 1)?;
    let client_resume = ClientSessionId::from_bytes(*session_id.as_bytes());

    // Real client: SS-UDP over XHTTP (h2 packet-up) to the edge, resuming the
    // home-shard id so the edge relays the datagram carrier over the mesh.
    let url = Url::parse(&format!("http://{}/ssu", edge.listen_addr))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let (transport, _issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        CipherKind::Chacha20IetfPoly1305,
        // sample_config's shared user "bob".
        "secret-b",
        None,
        false,
        "cluster-udp-xhttp-test",
        None,
        Some(client_resume),
        // Split UDP path, so no combined-path discriminator.
        None,
    )
    .await?;

    // One SS-UDP datagram, relayed edge→mesh→home→NAT→target and echoed back.
    // `send_packet` encrypts the SOCKS5 target header + payload as one packet.
    transport.send_packet(&ss_first_chunk(target_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    assert!(
        reply.ends_with(b"ping"),
        "SS-UDP-over-XHTTP datagram relayed home→edge→client byte-exact: {reply:?}",
    );

    transport.close().await?;
    Ok(())
}

/// SS-UDP relays over the HTTP/3 carrier too. An h3 client CONNECTs `/udp` on an
/// h3 edge with a home-shard resume id; the edge splices the h3 WebSocket to the
/// mesh with datagram framing (`edge_relay_h3_udp`), and the home forwards to
/// the target. A byte-exact echo proves the h3 SS-UDP accept branch end to end
/// (the `H3Ws` carrier, a different `WsSocket` impl than the h1/h2 path).
#[tokio::test]
async fn cluster_udp_h3_relays_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-h3-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Home: a plain-WS node with the mesh listener (carrier-agnostic home side);
    // edge: an h3 node that relays a foreign-shard resume.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_h3_edge_node(PSK, 2, peers, Duration::from_secs(4)).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;

    // h3 client → edge, CONNECT `/udp` presenting the home-shard resume id.
    let mut endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(test_h3_client_config(edge.cert_der.clone())?);
    let connection = endpoint.connect(edge.addr, "localhost")?.await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver_task =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost:{}/udp", edge.addr.port()))
        .version(Version::HTTP_3)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header("x-outline-resume-capable", "1")
        .header("x-outline-resume", session_id.to_hex())
        .extension(H3Protocol::WEBSOCKET)
        .body(())?;
    let mut req_stream = send_request.send_request(request).await?;
    let response = req_stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK, "h3 CONNECT /udp must succeed on the edge");

    let h3_stream = H3Stream::<H3Transport>::from_h3_client(req_stream);
    let mut socket = H3WebSocketStream::from_raw(h3_stream, H3Role::Client, H3WsConfig::default());

    // One SS-UDP datagram, relayed edge→mesh→home→NAT→target and echoed back.
    let mut plaintext = TargetAddr::from(target_addr).to_wire_bytes()?;
    plaintext.extend_from_slice(b"h3-udp");
    socket
        .send(H3Message::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
        .await?;

    let reply = tokio::time::timeout(Duration::from_secs(5), socket.next()).await?;
    let bytes = match reply {
        Some(Ok(H3Message::Binary(b))) => b,
        other => bail!("expected a binary SS-UDP reply over the h3 edge, got {other:?}"),
    };
    let decoded = decrypt_udp_packet(std::slice::from_ref(&user), &bytes)?;
    assert!(
        decoded.payload.ends_with(b"h3-udp"),
        "SS-UDP-over-h3 datagram relayed home→edge→client byte-exact",
    );

    driver_task.abort();
    Ok(())
}

/// VLESS-UDP rides the VlessTcp mesh carrier — there is no dedicated `VlessUdp`
/// carrier kind. The edge marks a VLESS carrier `VlessTcp` (it never inspects
/// the UDP command inside the still-encrypted VLESS byte stream) and forwards it
/// verbatim; the home's `run_vless_relay` parses `VlessCommand::Udp` out of the
/// stream and forwards to the target. This proves that path end to end — the U0
/// assumption behind not adding a `VlessUdp` carrier kind.
#[tokio::test]
async fn cluster_vless_udp_relays_via_vless_tcp() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-udp-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Home owns shard 1 (mesh listener); the edge (shard 2) relays to it. Both
    // register the shared VLESS user on `/vless` via `build_cluster_parts`.
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // Home-shard resume id: the edge relays the VLESS carrier (marked VlessTcp).
    let session_id = resume_id_for_shard(PSK, 1)?;
    let (mut socket, _) = connect_ws_h1(edge.listen_addr, "/vless", Some(session_id), true).await?;

    socket
        .send(WsMessage::Binary(vless_udp_request(
            CLUSTER_VLESS_UUID,
            target_addr,
            b"vless-udp",
        )?))
        .await?;

    // Standard VLESS response header, then the echoed length-prefixed datagram.
    let header = expect_binary_reply(&mut socket).await?;
    assert_eq!(header.as_ref(), &[VLESS_VERSION, 0x00], "VLESS response header over the relay");
    let echoed = expect_binary_reply(&mut socket).await?;
    assert_eq!(
        &echoed[2..],
        b"vless-udp",
        "VLESS-UDP datagram relayed edge→mesh→home→target byte-exact",
    );

    socket.close(None).await?;
    Ok(())
}
