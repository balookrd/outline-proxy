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

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use axum::http::{Method, Request, StatusCode, Version, header};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use h3::ext::Protocol as H3Protocol;
use outline_transport::{
    CarrierPadding, DnsCache as ClientDnsCache, SessionId as ClientSessionId, SsPathKind,
    TcpShadowsocksReader, TcpShadowsocksWriter, TransportMode, UdpWsTransport,
    UpstreamTransportGuard, init_carrier_padding,
};
use outline_wire::cluster::{ObfuscationKey, ShardId};
use outline_wire::padding::{ControlSignal, PaddingDecoder, PaddingScheme, encode_frame_into};
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
use super::super::super::transport::carrier_padding;
use super::super::super::transport::mesh_relay::run_mesh_listener;
use super::super::super::{
    AuthPolicy, DnsCache, H3ServeCtx, RouteRegistry, Services, UdpServices, build_app,
    build_transport_route_map, build_user_routes, ensure_rustls_provider_installed,
    serve_h3_server, user_keys,
};
use super::super::{
    connect_websocket_with_resume, cross_repo_install_test_tls_root_on_client,
    cross_repo_test_server_tls_config, sample_config, test_h3_client_config, test_h3_server_tls,
};
use super::ss::ss_handshake_frame;
use super::vless::vless_udp_request;
use super::{
    connect_ws_h1, expect_binary_reply, spawn_delayed_echo_udp_target, spawn_echo_target,
    spawn_echo_udp_target,
};
use crate::config::{CipherKind, ClusterConfig, ClusterPsk, H3Alpn, PaddingConfig};
use crate::crypto::{
    AeadStreamDecryptor, AeadStreamEncryptor, UserKey, decrypt_udp_packet, encrypt_udp_packet,
};
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
// One optional carrier-path arg per route table the various node spawners wire;
// bundling them into a struct would only move the noise, so allow the count.
#[allow(clippy::too_many_arguments)]
fn build_cluster_parts(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    xhttp_ss_path: Option<&str>,
    xhttp_ss_udp_path: Option<&str>,
    ss_tcp_path: Option<&str>,
    ws_ss_path: Option<&str>,
) -> Result<ClusterParts> {
    // The mesh QUIC endpoint needs the process-wide rustls provider installed.
    ensure_rustls_provider_installed();

    let mut config = sample_config((Ipv4Addr::LOCALHOST, 0).into());
    config.session_resumption.enabled = true;
    // The throttle e2e serves SS on its own padded path so enabling padding for
    // it (a process-global) never touches the other tests' `/tcp` carriers.
    if let Some(path) = ss_tcp_path {
        config.ws_path_tcp = path.to_string();
    }
    // A combined WS-SS base: `ws_path_ss` routes both the TCP and UDP legs onto
    // one path, so it lands in both WS route tables and `build_app` registers a
    // combined `<base>/{token}` upgrade (mirrors the owner's `ws_path_ss` config).
    if let Some(path) = ws_ss_path {
        config.ws_path_ss = Some(path.to_string());
    }
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
    let cluster = ClusterCtx::build(&cluster_cfg, Arc::clone(&metrics))?;
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
    } = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        xhttp_ss_path,
        xhttp_ss_udp_path,
        None,
        None,
    )?;

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

/// Boots a WS cluster node whose SS base path is *combined*: `ws_ss_path` puts
/// both the TCP and UDP legs on one base, so `build_app` registers a combined
/// `<base>/{token}` upgrade instead of the split `/tcp` + `/udp` routes. The
/// combined-SS counterpart of [`spawn_cluster_node`], used to exercise the
/// combined-WS SS-UDP leg (`combined_websocket_upgrade` → `udp_upgrade_for_path`)
/// in cluster mode.
async fn spawn_combined_ws_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    ws_ss_path: &str,
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
    } = build_cluster_parts(psk, shard, peers, budget, None, None, None, Some(ws_ss_path))?;

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

/// Boots a WS cluster node serving SS on a custom path (the throttle e2e). Same
/// wiring as [`spawn_cluster_node`], but the SS route lives on `ss_tcp_path` so
/// the process-global padding this test enables for that path never touches the
/// other tests' `/tcp` carriers.
async fn spawn_throttle_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    ss_tcp_path: &str,
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
    } = build_cluster_parts(psk, shard, peers, budget, None, None, Some(ss_tcp_path), None)?;

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
    } = build_cluster_parts(psk, shard, peers, budget, None, None, None, None)?;
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

/// A running h3 cluster node reachable by the *real* client (`UdpWsTransport`
/// over `WsH3`): it binds the shared cross-repo test cert (so the client's
/// installed root trusts it) instead of the per-call self-signed cert the raw
/// quinn probes use. Aborts its task on drop.
struct H3ClientNode {
    addr: SocketAddr,
    h3_task: JoinHandle<Result<()>>,
}

impl Drop for H3ClientNode {
    fn drop(&mut self) {
        self.h3_task.abort();
    }
}

/// Boots an h3 cluster node whose SS base path is *combined* over XHTTP
/// (`xhttp_path` in both the `xhttp_ss` and `xhttp_ss_udp` tables), served over
/// HTTP/3 with the cluster wired and a cert the real client trusts. Exercises
/// the h3 XHTTP combined-SS resolve (`handle_h3_request`'s `xhttp_ss` +
/// `xhttp_ss_udp` decode) → `handle_xhttp_h3_request` SS-UDP accept — the
/// owner's actual carrier for combined-SS. No mesh listener: a single node
/// serves cold-start datagrams locally.
async fn spawn_combined_xhttp_h3_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    xhttp_path: &str,
) -> Result<(H3ClientNode, UserKey)> {
    cross_repo_install_test_tls_root_on_client();
    let tls_config = cross_repo_test_server_tls_config(&[b"h3"]);
    let server = H3WebSocketServer::<H3Transport>::bind(
        (Ipv4Addr::LOCALHOST, 0).into(),
        tls_config,
        H3WsConfig::default(),
    )
    .await?;
    let addr = server.local_addr()?;

    let ClusterParts {
        routes, services, auth, cluster, user, ..
    } = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        Some(xhttp_path),
        Some(xhttp_path),
        None,
        None,
    )?;
    let ctx = H3ServeCtx {
        routes,
        services,
        auth,
        alpn: Arc::from(vec![H3Alpn::H3].into_boxed_slice()),
        http_fallback: None,
        cluster: Some(cluster),
    };
    let h3_task = tokio::spawn(serve_h3_server(server, ctx, ShutdownSignal::never()));

    Ok((H3ClientNode { addr, h3_task }, user))
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

/// A TCP target that floods `bytes` of data at every connection, so the home has
/// far more downlink to push than the (stalled) client will drain — the setup
/// the edge throttle detector needs. Ignores the client's request payload.
async fn spawn_flood_target(bytes: usize) -> Result<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let chunk = vec![0xA5u8; 64 * 1024];
                let mut written = 0;
                while written < bytes {
                    if stream.write_all(&chunk).await.is_err() {
                        return;
                    }
                    written += chunk.len();
                }
                // Keep the upstream open after the flood so the home's data
                // channel drains to empty (not closed): the ws_writer's biased
                // select services the throttle signal only in that lull, emitting
                // the OCTL instead of tearing the session down on upstream EOF.
                std::future::pending::<()>().await;
            });
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

/// Multi-megabyte round trip through the mesh relay, verified byte-exact with
/// SHA-256 in both directions (CLUSTER open risk #1: the mesh data plane has no
/// unit tests and needs large-transfer integrity coverage, mirroring the TUN
/// pump). Unlike the single-frame 512 KiB check, this streams 16 MiB as one
/// continuous SS-AEAD stream chunked across ~64 WebSocket frames each way, so
/// the relay's mesh read-chunk reassembly runs over the many-chunk regime where
/// a coalescing / reordering / truncation bug would actually surface. Uplink and
/// downlink run concurrently so the round trip cannot deadlock on buffer
/// capacity, and the transfer is hashed as it streams rather than buffered whole.
#[tokio::test]
async fn cluster_relay_streams_large_transfer_sha256() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-sha256-psk";
    const TOTAL: usize = 16 * 1024 * 1024;
    const CHUNK: usize = 256 * 1024;

    let (echo_addr, _accepts) = spawn_echo_target().await?;
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(8), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(8), None, None).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;

    // Deterministic 16 MiB payload and its reference SHA-256.
    let payload: Vec<u8> = (0..TOTAL)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let sent_digest = ring::digest::digest(&ring::digest::SHA256, &payload);

    let (socket, _) = connect_ws_h1(edge.listen_addr, "/tcp", Some(session_id), true).await?;
    let (mut sink, mut stream) = socket.split();

    // Uplink task: one continuous SS-AEAD stream, chunked across WS frames. The
    // first frame carries the target header + first data chunk; the rest are
    // continuation data on the same stream (fresh salt once, incrementing nonce).
    let user_for_send = user.clone();
    let send_payload = payload.clone();
    let send_task = tokio::spawn(async move {
        let mut enc = AeadStreamEncryptor::new(&user_for_send, None)?;
        let head = CHUNK.min(send_payload.len());
        let mut first = TargetAddr::from(echo_addr).to_wire_bytes()?;
        first.extend_from_slice(&send_payload[..head]);
        let mut buf = BytesMut::new();
        enc.encrypt_chunk(&first, &mut buf)?;
        sink.send(WsMessage::Binary(buf.freeze())).await?;
        for chunk in send_payload[head..].chunks(CHUNK) {
            let mut buf = BytesMut::new();
            enc.encrypt_chunk(chunk, &mut buf)?;
            sink.send(WsMessage::Binary(buf.freeze())).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    // Downlink: decrypt the echoed stream and hash it as it arrives.
    let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user].into_boxed_slice()));
    let mut recv_ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut plaintext = Vec::new();
    let mut received = 0usize;
    while received < TOTAL {
        let next = tokio::time::timeout(Duration::from_secs(30), stream.next()).await?;
        match next {
            Some(Ok(WsMessage::Binary(bytes))) => {
                decryptor.feed_ciphertext(&bytes);
                plaintext.clear();
                decryptor.drain_plaintext(&mut plaintext)?;
                recv_ctx.update(&plaintext);
                received += plaintext.len();
            },
            Some(Ok(WsMessage::Close(_))) | None => break,
            // Ignore any control frames the carrier may surface.
            Some(Ok(_)) => {},
            Some(Err(error)) => bail!("edge websocket error: {error}"),
        }
    }
    send_task.await??;

    assert_eq!(received, TOTAL, "relayed byte count differs from the {TOTAL}-byte transfer");
    assert_eq!(
        recv_ctx.finish().as_ref(),
        sent_digest.as_ref(),
        "SHA-256 mismatch: the mesh relay corrupted or reordered the large transfer"
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

/// COLD-START reproduction: a clustered node must serve an SS-UDP datagram
/// LOCALLY when the client presents NO resume id. After a client process restart
/// the resume cache is empty, so the first UDP dial carries no
/// `X-Outline-Resume` → `decide` = Local → no mesh relay is involved. This is
/// the path reported dead on the owner's fleet, so it must round-trip here.
#[tokio::test]
async fn cluster_node_udp_local_no_resume_roundtrips() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-local-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    // Single clustered node (shard 1), no peers. A cold-start client presents no
    // resume id, so the node serves the datagram itself (Local, not relayed).
    let (node, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let (mut socket, _) = connect_ws_h1(node.listen_addr, "/udp", None, true).await?;

    let payload = b"cold-start-local-datagram";
    let mut plaintext = TargetAddr::from(target_addr).to_wire_bytes()?;
    plaintext.extend_from_slice(payload);
    socket
        .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
        .await?;

    let reply = expect_binary_reply(&mut socket).await?;
    let decoded = decrypt_udp_packet(std::slice::from_ref(&user), &reply)?;
    assert!(
        decoded.payload.ends_with(payload),
        "cold-start SS-UDP (no resume) must round-trip locally on a clustered node",
    );
    socket.close(None).await?;
    Ok(())
}

/// COLD-START reproduction for **combined-SS over XHTTP** on a clustered node —
/// the exact intersection reported dead on the owner's fleet (combined-SS,
/// XHTTP carrier, cluster mode, no resume id). The base path is registered in
/// BOTH the `xhttp_ss` and `xhttp_ss_udp` tables (same path → `build_app` tags
/// it `SsCombined`), and the real client dials the UDP leg with the hidden UDP
/// discriminator (`SsPathKind::Udp`) over XHTTP-h2, presenting no resume id.
/// `edge_route` decides Local, so the node serves the datagram itself and
/// `resolve_route` must decode the discriminator to the `xhttp_ss_udp` table.
/// The echo must round-trip.
#[tokio::test]
async fn cluster_node_udp_combined_xhttp_no_resume_roundtrips() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-combined-xhttp-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    // Single clustered node (shard 1), no peers. `/ssc` is combined: the same
    // path lives in both the `xhttp_ss` and `xhttp_ss_udp` tables.
    let (node, _user) = spawn_cluster_node(
        PSK,
        1,
        HashMap::new(),
        Duration::from_secs(4),
        Some("/ssc"),
        Some("/ssc"),
    )
    .await?;

    let url = Url::parse(&format!("http://{}/ssc", node.listen_addr))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // Faithful cold start: the real client always dials via `connect_with_resume`,
    // so it advertises `Resume-Capable: 1` even with no resume id. The server
    // then mints an issued session id and the SS-UDP relay keys its NAT entry
    // under the per-session scope (the 6d17e73 fix) — a different code path than
    // a `Resume-Capable`-less third-party client, and the one the owner hits.
    let (transport, issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        CipherKind::Chacha20IetfPoly1305,
        // sample_config's shared user "bob".
        "secret-b",
        None,
        false,
        "cluster-udp-combined-xhttp-test",
        None,
        // Cold start: no resume id to present.
        None,
        // Combined path → encode the hidden UDP discriminator in the session id.
        Some(SsPathKind::Udp),
    )
    .await?;
    assert!(issued.is_some(), "a Resume-Capable cold dial must be issued a session id");

    transport.send_packet(&ss_first_chunk(target_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    assert!(
        reply.ends_with(b"ping"),
        "cold-start combined-SS-UDP over XHTTP must round-trip locally on a clustered node: {reply:?}",
    );

    transport.close().await?;
    Ok(())
}

/// RESUME reproduction for **combined-SS over XHTTP**: an edge relays a
/// home-shard resume id to the home over the mesh (`SsUdpXhttp` carrier,
/// datagram-framed), and the home must resolve the combined base path on its
/// `xhttp_ss_udp` table. The combined counterpart of
/// `cluster_udp_xhttp_relays_to_home` (which uses the split `/ssu` path).
#[tokio::test]
async fn cluster_udp_combined_xhttp_relays_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-combined-xhttp-relay-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Home resolves the combined `/ssc` (both xhttp tables) and runs the mesh
    // listener; the edge serves `/ssc` and relays a foreign-shard resume.
    let (home, _user) = spawn_cluster_node(
        PSK,
        1,
        HashMap::new(),
        Duration::from_secs(4),
        Some("/ssc"),
        Some("/ssc"),
    )
    .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) =
        spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), Some("/ssc"), Some("/ssc"))
            .await?;

    let session_id = resume_id_for_shard(PSK, 1)?;
    let client_resume = ClientSessionId::from_bytes(*session_id.as_bytes());

    let url = Url::parse(&format!("http://{}/ssc", edge.listen_addr))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let (transport, _issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        CipherKind::Chacha20IetfPoly1305,
        "secret-b",
        None,
        false,
        "cluster-udp-combined-xhttp-relay-test",
        None,
        Some(client_resume),
        Some(SsPathKind::Udp),
    )
    .await?;

    transport.send_packet(&ss_first_chunk(target_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    assert!(
        reply.ends_with(b"ping"),
        "combined-SS-UDP over XHTTP must relay home→edge→client byte-exact: {reply:?}",
    );

    transport.close().await?;
    Ok(())
}

/// COLD-START reproduction for **combined-SS over WebSocket** on a clustered
/// node: `ws_path_ss` puts the TCP and UDP legs on one base, so the client
/// dials `<base>/{token}` with the hidden UDP discriminator and the server
/// routes it through `combined_websocket_upgrade` → `udp_upgrade_for_path`
/// with the COMBINED base path. On a cold start `edge_route` decides Local, so
/// the node must resolve the base on its `udp` (WS) table and round-trip the
/// echo. The WS twin of `cluster_node_udp_combined_xhttp_no_resume_roundtrips`.
#[tokio::test]
async fn cluster_node_udp_combined_ws_no_resume_roundtrips() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-combined-ws-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    // Single clustered node (shard 1), no peers. `/ssc` is a combined WS base.
    let (node, _user) =
        spawn_combined_ws_node(PSK, 1, HashMap::new(), Duration::from_secs(4), "/ssc").await?;

    let url = Url::parse(&format!("ws://{}/ssc", node.listen_addr))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // Faithful cold start (see the XHTTP twin): `connect_with_resume` with no id
    // still advertises `Resume-Capable`, so the server mints an issued id and the
    // SS-UDP relay uses the per-session NAT scope. The combined WS dial appends
    // the `/{token}` UDP discriminator segment onto the base path.
    let (transport, issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &url,
        TransportMode::WsH1,
        CipherKind::Chacha20IetfPoly1305,
        "secret-b",
        None,
        false,
        "cluster-udp-combined-ws-test",
        None,
        None,
        Some(SsPathKind::Udp),
    )
    .await?;
    assert!(issued.is_some(), "a Resume-Capable cold dial must be issued a session id");

    transport.send_packet(&ss_first_chunk(target_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    assert!(
        reply.ends_with(b"ping"),
        "cold-start combined-SS-UDP over WS must round-trip locally on a clustered node: {reply:?}",
    );

    transport.close().await?;
    Ok(())
}

/// RESUME reproduction for **combined-SS over WebSocket**: an edge relays a
/// home-shard resume id to the home over the mesh (`SsUdp` carrier,
/// datagram-framed), and the home must resolve the combined base path on its
/// `udp` (WS) table. The WS twin of `cluster_udp_combined_xhttp_relays_to_home`.
#[tokio::test]
async fn cluster_udp_combined_ws_relays_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-combined-ws-relay-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Home resolves the combined `/ssc` (WS `udp` table) and runs the mesh
    // listener; the edge serves `/ssc` and relays a foreign-shard resume.
    let (home, _user) =
        spawn_combined_ws_node(PSK, 1, HashMap::new(), Duration::from_secs(4), "/ssc").await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_combined_ws_node(PSK, 2, peers, Duration::from_secs(4), "/ssc").await?;

    let session_id = resume_id_for_shard(PSK, 1)?;
    let client_resume = ClientSessionId::from_bytes(*session_id.as_bytes());

    let url = Url::parse(&format!("ws://{}/ssc", edge.listen_addr))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let (transport, _issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &url,
        TransportMode::WsH1,
        CipherKind::Chacha20IetfPoly1305,
        "secret-b",
        None,
        false,
        "cluster-udp-combined-ws-relay-test",
        None,
        Some(client_resume),
        Some(SsPathKind::Udp),
    )
    .await?;

    transport.send_packet(&ss_first_chunk(target_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    assert!(
        reply.ends_with(b"ping"),
        "combined-SS-UDP over WS must relay home→edge→client byte-exact: {reply:?}",
    );

    transport.close().await?;
    Ok(())
}

/// The padded carrier path the combined-SS-UDP padding e2e uses. Distinct from
/// the unpadded `/ssc` the other combined tests use, so the process-global
/// server padding config (`carrier_padding::init`, first-call-wins) never pads
/// those carriers. Padding is config-synchronised (no on-wire capability bit),
/// so client and server must both opt in on this path or the padded frames fail
/// the SS-UDP decryptor.
const COMBINED_PADDED_PATH: &str = "/ssc-pad";

/// Wires the process-global padding on both sides for [`COMBINED_PADDED_PATH`]:
/// the server pads that path, and the client's per-dial scheme parameters are
/// installed (the actual on/off is a per-dial override the caller wraps around
/// its dial). Both inits are first-call-wins process globals, so this is safe to
/// call from more than one test — every caller passes the same config.
///
/// NOTE: `carrier_padding::init` is a process-global shared with the (ignored)
/// `cluster_edge_throttle_hint_injects_octl_to_client` test. Under a normal
/// `cargo test` run that test is skipped, so this config wins deterministically;
/// only a `--include-ignored` run can race the two, and they scope to different
/// paths so the loser's path simply stays unpadded.
fn enable_combined_padding_globals() {
    carrier_padding::init(PaddingConfig {
        enabled: true,
        min_bytes: 4,
        max_bytes: 32,
        cover: false,
        cover_jitter_min_ms: 0,
        cover_jitter_max_ms: 0,
        paths: vec![COMBINED_PADDED_PATH.to_string()],
        throttle_detect_enabled: false,
        throttle_ratio_percent: 200,
        throttle_window_secs: 1,
        throttle_sustain_windows: 1,
        throttle_min_bytes_per_sec: 0,
        throttle_edge_min_bytes_per_sec: 0,
        throttle_signal_cooldown_secs: 1,
    });
    init_carrier_padding(
        CarrierPadding {
            scheme: PaddingScheme::new(4, 32),
            cover: false,
            cover_jitter_min_ms: 0,
            cover_jitter_max_ms: 0,
        },
        // Default off: only the padded dial (wrapped in the per-uplink override
        // scope) pads; every other dial in the binary stays on the plain wire.
        false,
    );
}

/// COLD-START reproduction for **padded combined-SS UDP over XHTTP** on a
/// clustered node — the owner's full setup (combined-SS, XHTTP carrier, cluster,
/// padding on, no resume id). The client wraps its dial in the per-uplink
/// padding override so `send_packet` frames each datagram; the clustered node
/// serves it locally and must decode the padding on its `xhttp_ss_udp` route
/// (padding resolved by the combined base path) before SS-UDP decrypt, then pad
/// the echo. A silent decode/route mismatch would drop every datagram — the
/// "arrives but no reply" symptom.
#[tokio::test]
async fn cluster_node_udp_combined_xhttp_padded_no_resume_roundtrips() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-combined-xhttp-pad-psk";
    enable_combined_padding_globals();
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    let (node, _user) = spawn_cluster_node(
        PSK,
        1,
        HashMap::new(),
        Duration::from_secs(4),
        Some(COMBINED_PADDED_PATH),
        Some(COMBINED_PADDED_PATH),
    )
    .await?;

    let url = Url::parse(&format!("http://{}{}", node.listen_addr, COMBINED_PADDED_PATH))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // Faithful cold start: `connect_with_resume` (no id) still advertises
    // `Resume-Capable`, wrapped in the per-uplink padding override so the dial
    // pads and the server mints an issued id (padded scoped-NAT path).
    let (transport, _issued, _downgraded) =
        outline_transport::carrier_padding::with_uplink_padding_override(
            true,
            UdpWsTransport::connect_with_resume(
                &cache,
                &url,
                TransportMode::XhttpH2,
                CipherKind::Chacha20IetfPoly1305,
                "secret-b",
                None,
                false,
                "cluster-udp-combined-xhttp-pad-test",
                None,
                None,
                Some(SsPathKind::Udp),
            ),
        )
        .await?;

    transport.send_packet(&ss_first_chunk(target_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    assert!(
        reply.ends_with(b"ping"),
        "padded cold-start combined-SS-UDP over XHTTP must round-trip locally on a clustered node: {reply:?}",
    );

    transport.close().await?;
    Ok(())
}

/// COLD-START reproduction for **padded combined-SS UDP over WebSocket** on a
/// clustered node: the WS twin of the XHTTP padded test. The client pads each
/// datagram; the node routes through `combined_websocket_upgrade` →
/// `udp_upgrade_for_path` and must resolve the padding scheme by the combined
/// base path (`scheme_for_path(&path)` with the base, not the `/{token}` URL) or
/// the padded datagram desyncs the decoder and is dropped.
#[tokio::test]
async fn cluster_node_udp_combined_ws_padded_no_resume_roundtrips() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-combined-ws-pad-psk";
    enable_combined_padding_globals();
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    let (node, _user) = spawn_combined_ws_node(
        PSK,
        1,
        HashMap::new(),
        Duration::from_secs(4),
        COMBINED_PADDED_PATH,
    )
    .await?;

    let url = Url::parse(&format!("ws://{}{}", node.listen_addr, COMBINED_PADDED_PATH))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // Faithful cold start: `connect_with_resume` (no id) still advertises
    // `Resume-Capable`, wrapped in the per-uplink padding override.
    let (transport, _issued, _downgraded) =
        outline_transport::carrier_padding::with_uplink_padding_override(
            true,
            UdpWsTransport::connect_with_resume(
                &cache,
                &url,
                TransportMode::WsH1,
                CipherKind::Chacha20IetfPoly1305,
                "secret-b",
                None,
                false,
                "cluster-udp-combined-ws-pad-test",
                None,
                None,
                Some(SsPathKind::Udp),
            ),
        )
        .await?;

    transport.send_packet(&ss_first_chunk(target_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    assert!(
        reply.ends_with(b"ping"),
        "padded cold-start combined-SS-UDP over WS must round-trip locally on a clustered node: {reply:?}",
    );

    transport.close().await?;
    Ok(())
}

/// COLD-START reproduction for **combined-SS UDP over XHTTP-HTTP/3** on a
/// clustered node — the owner's actual carrier (combined-SS, XHTTP over H3,
/// cluster, no resume). The real client dials `UdpWsTransport` in XhttpH3
/// (packet-up over QUIC) with the hidden UDP discriminator; the h3 request
/// handler resolves the combined base on `xhttp_ss_udp` and serves it locally
/// (cluster `edge_route` decides Local on a cold start). The h3 request path is
/// distinct from the h1/h2 axum XHTTP handler, so it is covered separately.
#[tokio::test]
async fn cluster_node_udp_combined_xhttp_h3_no_resume_roundtrips() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-combined-xhttp-h3-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    let (node, _user) =
        spawn_combined_xhttp_h3_node(PSK, 1, HashMap::new(), Duration::from_secs(4), "/ssc")
            .await?;

    // h3 mandates `https://`; the shared test root was installed on the client
    // by `spawn_combined_xhttp_h3_node`, so the dial trusts the self-signed cert.
    let url = Url::parse(&format!("https://localhost:{}/ssc", node.addr.port()))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    // Faithful cold start (see the h2 twin): `connect_with_resume` with no id
    // still advertises `Resume-Capable`, exercising the issued-id / scoped-NAT
    // path over the QUIC carrier.
    let (transport, issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH3,
        CipherKind::Chacha20IetfPoly1305,
        "secret-b",
        None,
        false,
        "cluster-udp-combined-xhttp-h3-test",
        None,
        None,
        Some(SsPathKind::Udp),
    )
    .await?;
    assert!(issued.is_some(), "a Resume-Capable cold dial must be issued a session id");

    transport.send_packet(&ss_first_chunk(target_addr, b"ping")).await?;
    let reply = transport.read_packet().await?;
    assert!(
        reply.ends_with(b"ping"),
        "cold-start combined-SS-UDP over XHTTP-h3 must round-trip locally on a clustered node: {reply:?}",
    );

    transport.close().await?;
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

/// Two *concurrent* SS-UDP sessions from the same user to the same target —
/// each relayed through a different edge to the same home — must not steal each
/// other's upstream responses. This is the mesh trigger for the shared
/// process-wide NAT's last-writer-wins response slot: the home keys a NAT entry
/// on `(user, fwmark, target)` only, so a second live carrier for the same
/// triple overwrites the first's `UdpResponseSender`, and the shared reader then
/// misroutes the first session's echo to the second (or drops it). VLESS-UDP is
/// immune because each session owns a dedicated socket + reader.
///
/// The reproduction is made deterministic by a delayed-echo target: carrier A's
/// datagram is held upstream while carrier B connects and registers, so A's echo
/// arrives *after* B has taken the shared response slot. Correct behaviour: A
/// still receives its own echo. Buggy behaviour: A times out (its echo went to
/// B). Uses two distinct home-shard resume ids so B is a genuinely separate
/// session, not a resume of A.
#[tokio::test]
async fn cluster_udp_concurrent_carriers_do_not_share_response_slot() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-collision-psk";
    // Hold each datagram upstream long enough for the second carrier to register
    // before the first carrier's echo comes back.
    let target_addr = spawn_delayed_echo_udp_target(Duration::from_millis(500)).await?;

    // Home owns shard 1; two edges (shards 2, 3) relay /udp to it.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(8), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge_a, _) =
        spawn_cluster_node(PSK, 2, peers.clone(), Duration::from_secs(8), None, None).await?;
    let (edge_b, _) = spawn_cluster_node(PSK, 3, peers, Duration::from_secs(8), None, None).await?;

    // Two DISTINCT home-shard sessions (not a resume of one another): both route
    // to the home, but each is its own carrier.
    let session_a = resume_id_for_shard(PSK, 1)?;
    let session_b = resume_id_for_shard(PSK, 1)?;
    assert_ne!(session_a, session_b, "the two sessions must be distinct");

    // Carrier A: register a NAT responder for `target_addr`, then send a datagram
    // whose echo the target will hold for 500 ms.
    let (mut sock_a, _) = connect_ws_h1(edge_a.listen_addr, "/udp", Some(session_a), true).await?;
    let mut plaintext_a = TargetAddr::from(target_addr).to_wire_bytes()?;
    plaintext_a.extend_from_slice(b"carrier-a-datagram");
    sock_a
        .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext_a)?.into()))
        .await?;

    // Give A's datagram time to reach the home, create the NAT entry and be
    // forwarded upstream (its echo is now pending in the target's delay).
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Carrier B: a second, concurrent session to the SAME (user, target). On the
    // buggy shared NAT it overwrites A's response slot on the home. B does not
    // send afterward, so the slot stays pointed at B when A's echo returns.
    let (mut sock_b, _) = connect_ws_h1(edge_b.listen_addr, "/udp", Some(session_b), true).await?;
    let mut plaintext_b = TargetAddr::from(target_addr).to_wire_bytes()?;
    plaintext_b.extend_from_slice(b"carrier-b-datagram");
    sock_b
        .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext_b)?.into()))
        .await?;

    // A's echo must come back to A — not be misrouted to B because B overwrote
    // the shared last-writer-wins response slot.
    let reply = expect_binary_reply(&mut sock_a)
        .await
        .context("carrier A never received its echo (misrouted to carrier B's stream)")?;
    let decoded = decrypt_udp_packet(std::slice::from_ref(&user), &reply)?;
    assert!(
        decoded.payload.ends_with(b"carrier-a-datagram"),
        "carrier A must receive its own echo, not carrier B's traffic",
    );

    sock_a.close(None).await?;
    sock_b.close(None).await?;
    Ok(())
}

/// A relayed SS-UDP carrier whose home does not serve the edge's path resolves
/// to an *empty* route table, so every datagram fails authentication and is
/// dropped. The home keys the relayed user lookup on the edge-supplied
/// `header.path`, so any home/edge path- or carrier-table mismatch is a silent
/// black hole (bug #2). This documents that failure mode — now made diagnosable
/// by `warn_if_empty_relayed_route` — and guards against a future change that
/// would silently weaken path scoping. Only reachable under an asymmetric
/// cluster config; a symmetric cluster (matching config, the supported topology)
/// always resolves the path, as `cluster_udp_relays_datagrams_to_home` and
/// `cluster_udp_xhttp_relays_to_home` cover across the `udp` and `xhttp_ss_udp`
/// tables respectively.
#[tokio::test]
async fn cluster_udp_relay_drops_when_home_lacks_the_path() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-emptyroute-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Build the home's cluster parts, then blank its `udp` route table so the
    // relayed carrier resolves to no users — an asymmetric-config home. Only the
    // mesh listener is needed (the client dials the edge, not the home's WS).
    let home = build_cluster_parts(
        PSK,
        1,
        HashMap::new(),
        Duration::from_secs(4),
        None,
        None,
        None,
        None,
    )?;
    {
        let snap = home.routes.load();
        home.routes.store(Arc::new(RouteRegistry {
            tcp: Arc::clone(&snap.tcp),
            udp: Arc::new(BTreeMap::new()),
            vless: Arc::clone(&snap.vless),
            xhttp_vless: Arc::clone(&snap.xhttp_vless),
            xhttp_ss: Arc::clone(&snap.xhttp_ss),
            xhttp_ss_udp: Arc::clone(&snap.xhttp_ss_udp),
        }));
    }
    let mesh_addr = home.mesh_addr;
    let user = home.user.clone();
    let _home_mesh = tokio::spawn(run_mesh_listener(
        home.cluster,
        home.services,
        home.routes,
        ShutdownSignal::never(),
    ));

    // Edge serves /udp normally and relays a shard-1 resume to the home.
    let peers = HashMap::from([(ShardId::new(1).unwrap(), mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;
    let (mut socket, _) = connect_ws_h1(edge.listen_addr, "/udp", Some(session_id), true).await?;

    let mut plaintext = TargetAddr::from(target_addr).to_wire_bytes()?;
    plaintext.extend_from_slice(b"into-the-void");
    socket
        .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
        .await?;

    // The home has no /udp users, so the datagram never authenticates and no echo
    // returns — the drop bug #2 describes.
    let reply = expect_binary_reply(&mut socket).await;
    assert!(
        reply.is_err(),
        "a relayed datagram to a home lacking the path must be dropped, got {reply:?}",
    );

    socket.close(None).await?;
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

/// A VLESS-UDP session migrates across an edge switch. VLESS-UDP rides the
/// VlessTcp mesh carrier (no dedicated `VlessUdp` kind); on carrier drop the
/// home parks a `Parked::VlessUdpSingle` under the carrier's home-shard session
/// id. Presenting that same id on a *different* edge relays to the same home,
/// whose `establish_vless_udp_upstream` resumes the parked `Arc<UdpSocket>`
/// instead of binding a fresh source port — so the target sees exactly one
/// upstream source across the switch, mirroring the SS-UDP
/// `cluster_udp_survives_edge_switch` guarantee.
///
/// This is the server half of client-side cross-node VLESS-UDP migration: the
/// client keeps each target's issued id in the durable
/// `global_vless_udp_resume_cache`, so a fresh mux on the new edge re-presents
/// the shard-carrying id and the edge relays it home.
#[tokio::test]
async fn cluster_vless_udp_survives_edge_switch() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-udp-switch-psk";
    let (target_addr, sources) = spawn_echo_udp_target().await?;

    // Home owns shard 1; two edges (shards 2, 3) relay the VlessTcp carrier to it.
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge_a, _) =
        spawn_cluster_node(PSK, 2, peers.clone(), Duration::from_secs(4), None, None).await?;
    let (edge_b, _) = spawn_cluster_node(PSK, 3, peers, Duration::from_secs(4), None, None).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;

    // Session #1 via edge A: the home misses (never parked) → fresh UDP socket,
    // parked on close under the id the client presented.
    let (mut sock_a, _) =
        connect_ws_h1(edge_a.listen_addr, "/vless", Some(session_id), true).await?;
    sock_a
        .send(WsMessage::Binary(vless_udp_request(
            CLUSTER_VLESS_UUID,
            target_addr,
            b"vless-a",
        )?))
        .await?;
    let header = expect_binary_reply(&mut sock_a).await?;
    assert_eq!(header.as_ref(), &[VLESS_VERSION, 0x00], "VLESS response header over edge A");
    let echoed = expect_binary_reply(&mut sock_a).await?;
    assert_eq!(&echoed[2..], b"vless-a", "edge A datagram relayed to target byte-exact");
    assert_eq!(
        sources.lock().await.len(),
        1,
        "first relay must open exactly one upstream source"
    );
    sock_a.close(None).await?;
    drop(sock_a);
    // Let the mesh stream finish and the home park the UDP session on the FIN.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Session #2 via edge B, same id: the home's `establish_vless_udp_upstream`
    // resumes the parked `Parked::VlessUdpSingle` and re-attaches its socket with
    // no fresh bind. The datagram reaches the target through the migrated session.
    let (mut sock_b, _) =
        connect_ws_h1(edge_b.listen_addr, "/vless", Some(session_id), true).await?;
    sock_b
        .send(WsMessage::Binary(vless_udp_request(
            CLUSTER_VLESS_UUID,
            target_addr,
            b"vless-b",
        )?))
        .await?;
    let reply = expect_binary_reply(&mut sock_b)
        .await
        .context("carrier B never received a reply after the edge switch")?;
    // A resume hit re-attaches the parked socket; the home replays the VLESS
    // response header on the new carrier, so tolerate either the header frame
    // (followed by the datagram) or the datagram directly.
    let echoed = if reply.as_ref() == [VLESS_VERSION, 0x00] {
        expect_binary_reply(&mut sock_b).await?
    } else {
        reply
    };
    assert_eq!(
        &echoed[2..],
        b"vless-b",
        "edge B datagram relayed to target byte-exact after the switch",
    );
    assert_eq!(
        sources.lock().await.len(),
        1,
        "resume across the edge switch must reuse the parked UDP socket (one upstream source)",
    );
    sock_b.close(None).await?;
    Ok(())
}

/// The whole edge→hint→home→OCTL→client path, end to end. With padding + throttle
/// detection enabled on a dedicated path, a client that stalls its downlink read
/// while the home floods it makes the edge's client-facing send block; the edge
/// detects the stall, sends a `THROTTLE_HINT` mesh datagram to the home, which
/// routes it to the relayed session's monitor and injects an `OCTL` cover frame.
/// The client decodes that frame as `ThrottleSwitchUplink`.
///
/// Padding is a process-global; it is scoped to this test's own path so the
/// other cluster tests' `/tcp` carriers stay unpadded (and nothing else in the
/// test binary calls `carrier_padding::init`).
///
/// `#[ignore]`d in CI: firing the edge detector needs a client-facing `send`
/// that blocks for longer than the 1s detection-window floor, which in turn
/// needs the socket buffers between home→mesh→edge→client to be *full*. Whether
/// a bounded flood fills them before the stall elapses depends on the OS's TCP
/// buffer autotuning (small on macOS, large on Linux) and on the edge send
/// buffer, which the test cannot size — so it passes locally but flakes on a
/// Linux CI runner where the flood is absorbed and no send blocks. The detector
/// itself (real THROTTLE_HINT over a real mesh + the stall/cooldown decision) is
/// covered deterministically by `mesh_relay`'s
/// `edge_detector_signals_throttle_hint_over_the_mesh` and the `StallTracker`
/// unit tests; the home route→signal→OCTL half by the `ThrottleRegistry` and
/// `ws_writer` tests. Run this one manually with `--ignored` to exercise the
/// full wire path.
#[tokio::test]
#[ignore = "backpressure/timing-dependent (OS TCP buffer sizes); covered deterministically elsewhere"]
async fn cluster_edge_throttle_hint_injects_octl_to_client() -> Result<()> {
    const PSK: &[u8] = b"cluster-throttle-octl-psk";
    const PATH: &str = "/throttle-e2e";

    carrier_padding::init(PaddingConfig {
        enabled: true,
        min_bytes: 1,
        max_bytes: 16,
        cover: false,
        cover_jitter_min_ms: 0,
        cover_jitter_max_ms: 0,
        paths: vec![PATH.to_string()],
        throttle_detect_enabled: true,
        throttle_ratio_percent: 200,
        // Window is floored at 1s; sustain 1 fires on a single >1s stalled send.
        throttle_window_secs: 1,
        throttle_sustain_windows: 1,
        throttle_min_bytes_per_sec: 0,
        // Floor off: this timing-driven e2e drives the stall directly and the
        // flood-throttled delivery rate is not what it asserts on.
        throttle_edge_min_bytes_per_sec: 0,
        throttle_signal_cooldown_secs: 1,
    });

    let flood_addr = spawn_flood_target(4 * 1024 * 1024).await?;
    let (home, user) =
        spawn_throttle_node(PSK, 1, HashMap::new(), Duration::from_secs(30), PATH).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_throttle_node(PSK, 2, peers, Duration::from_secs(30), PATH).await?;

    let session_id = resume_id_for_shard(PSK, 1)?;
    let (socket, _) = connect_ws_h1(edge.listen_addr, PATH, Some(session_id), true).await?;
    let (mut sink, mut stream) = socket.split();

    // Padded uplink: the home decodes padding on this path before AEAD, so wrap
    // the SS handshake+request in one padding frame (empty pad is a valid frame).
    let ss = ss_handshake_frame(&user, flood_addr, b"flood")?;
    let mut framed = Vec::new();
    encode_frame_into(&mut framed, &ss, &[]).expect("padding frame within u16 bounds");
    sink.send(WsMessage::Binary(framed.into())).await?;

    // Stall the downlink read past one detection window: the edge's client-facing
    // send blocks, and when it finally completes it records a >1s stall and fires
    // the hint.
    tokio::time::sleep(Duration::from_millis(1600)).await;

    // Resume reading and decode the padding stream until the OCTL control frame
    // surfaces. The SS plaintext is irrelevant here, so the decode sink is reused
    // and discarded — only the control signal matters.
    let mut decoder = PaddingDecoder::new();
    let mut discard = Vec::new();
    let got_octl = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match stream.next().await {
                Some(Ok(WsMessage::Binary(bytes))) => {
                    discard.clear();
                    decoder.push(&bytes, &mut discard);
                    if matches!(decoder.take_control(), Some(ControlSignal::ThrottleSwitchUplink)) {
                        return true;
                    }
                },
                Some(Ok(WsMessage::Close(_))) | None => return false,
                Some(Ok(_)) => {},
                Some(Err(_)) => return false,
            }
        }
    })
    .await;

    assert!(
        matches!(got_octl, Ok(true)),
        "client must decode an OCTL ThrottleSwitchUplink cover frame injected by the home \
         after the edge signalled the throttled client segment (got {got_octl:?})",
    );
    Ok(())
}
