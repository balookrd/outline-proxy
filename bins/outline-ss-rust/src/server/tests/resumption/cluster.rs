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
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use h3::ext::Protocol as H3Protocol;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper_util::rt::{TokioExecutor, TokioIo};
use outline_transport::{
    CarrierPadding, DnsCache as ClientDnsCache, SessionId as ClientSessionId, SsPathKind,
    TcpShadowsocksReader, TcpShadowsocksWriter, TransportMode, UdpWsTransport,
    UpstreamTransportGuard, init_carrier_padding,
};
use outline_wire::cluster::{ObfuscationKey, ShardId};
use outline_wire::padding::{ControlSignal, PaddingDecoder, PaddingScheme, encode_frame_into};
use outline_wire::resume::{
    ACK_PREFIX_HEADER, FRAME_LEN_V1, ParseResult, RESUME_CAPABLE_HEADER, RESUME_REQUEST_HEADER,
    SESSION_RESPONSE_HEADER, SYMMETRIC_REPLAY_HEADER, parse_v1,
};
use quinn::Endpoint;
use ring::rand::SystemRandom;
use rustls::pki_types::CertificateDer;
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, Message as H3Message, Role as H3Role,
    Stream as H3Stream, WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
};
use std::convert::Infallible;
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
use super::super::xhttp::http_client;
use super::super::{
    connect_websocket_with_resume, cross_repo_install_test_tls_root_on_client,
    cross_repo_test_server_tls_config, sample_config, test_h3_client_config, test_h3_server_tls,
};
use super::ss::ss_handshake_frame;
use super::vless::{
    collect_mux_keep_payloads, vless_mux_new_tcp_frame, vless_mux_request, vless_tcp_request,
    vless_udp_request,
};
use super::{
    connect_ws_h1, connect_ws_h1_ack_prefix, expect_binary_reply, spawn_delayed_echo_udp_target,
    spawn_echo_target, spawn_echo_udp_target,
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

/// `downlink_buffer_bytes` for the nodes that must have v2 Symmetric Downlink
/// Replay enabled in their own resumption config. Any non-zero value flips
/// `OrphanRegistry::symmetric_replay_enabled`; the size itself is irrelevant to
/// these tests, which never fill the ring.
const V2_DOWNLINK_BUFFER_BYTES: usize = 64 * 1024;

/// A running cluster node: an SS-over-WS listener plus a mesh endpoint (home
/// listener + edge dialer). Aborts its tasks on drop so tests don't leak
/// listeners between cases.
struct ClusterNode {
    listen_addr: SocketAddr,
    mesh_addr: SocketAddr,
    /// This node's park registry, so a test can wait for a session to land
    /// rather than sleeping for it.
    registry: Arc<OrphanRegistry>,
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
    downlink_buffer_bytes: usize,
) -> Result<ClusterParts> {
    // The mesh QUIC endpoint needs the process-wide rustls provider installed.
    ensure_rustls_provider_installed();

    let mut config = sample_config((Ipv4Addr::LOCALHOST, 0).into());
    config.session_resumption.enabled = true;
    // Non-zero turns on the v2 Symmetric Downlink Replay protocol for this
    // node's *own* negotiation (`OrphanRegistry::symmetric_replay_enabled`).
    // Zero — every node but the v2 edge — leaves v2 off, as before.
    config.session_resumption.downlink_buffer_bytes = downlink_buffer_bytes;
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
        crate::server::transport::XhttpRegistryLimits::unbounded(),
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
    let parts = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        xhttp_ss_path,
        xhttp_ss_udp_path,
        None,
        None,
        0,
    )?;
    boot_ws_node(parts).await
}

/// Serves built [`ClusterParts`] over a freshly bound localhost TCP listener:
/// the axum carrier app plus this node's mesh listener (the home half). Every WS
/// node spawner below differs only in the config it hands `build_cluster_parts`,
/// so the wiring lives here once.
async fn boot_ws_node(parts: ClusterParts) -> Result<(ClusterNode, UserKey)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let ClusterParts {
        routes,
        services,
        auth,
        cluster,
        mesh_addr,
        user,
    } = parts;

    let app = build_app(
        Arc::clone(&routes),
        Arc::clone(&services),
        auth,
        None,
        Some(Arc::clone(&cluster)),
    );
    let registry = Arc::clone(&services.orphan_registry);
    let ws_task =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });
    let mesh_task =
        tokio::spawn(run_mesh_listener(cluster, services, routes, ShutdownSignal::never()));

    Ok((
        ClusterNode {
            listen_addr,
            mesh_addr,
            registry,
            ws_task,
            mesh_task,
        },
        user,
    ))
}

/// Boots an SS-over-XHTTP cluster node whose own resumption config has v2
/// Symmetric Downlink Replay **enabled** (`downlink_buffer_bytes > 0`).
///
/// That is what makes it the right edge for
/// [`cluster_xhttp_edge_echo_withholds_symmetric_replay`]: only a node that can
/// confirm v2 locally would echo v2 from a request-derived negotiation, so the
/// test's "v2 must be withheld" assertion actually discriminates between the
/// relayed echo and the local one.
async fn spawn_xhttp_v2_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    xhttp_ss_path: &str,
) -> Result<(ClusterNode, UserKey)> {
    let parts = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        Some(xhttp_ss_path),
        None,
        None,
        None,
        V2_DOWNLINK_BUFFER_BYTES,
    )?;
    boot_ws_node(parts).await
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
    let parts =
        build_cluster_parts(psk, shard, peers, budget, None, None, None, Some(ws_ss_path), 0)?;
    boot_ws_node(parts).await
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
    let parts =
        build_cluster_parts(psk, shard, peers, budget, None, None, Some(ss_tcp_path), None, 0)?;
    boot_ws_node(parts).await
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
    let parts = build_cluster_parts(psk, shard, peers, budget, None, None, None, None, 0)?;
    boot_h3_edge_node(parts).await
}

/// The XHTTP-over-h3 twin of [`spawn_h3_edge_node`]: the same edge, but serving
/// an SS-over-XHTTP base path and with v2 Symmetric Downlink Replay enabled in
/// its own resumption config — see [`spawn_xhttp_v2_node`] for why the test
/// needs that.
async fn spawn_xhttp_h3_v2_edge_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    xhttp_ss_path: &str,
) -> Result<(H3EdgeNode, UserKey)> {
    let parts = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        Some(xhttp_ss_path),
        None,
        None,
        None,
        V2_DOWNLINK_BUFFER_BYTES,
    )?;
    boot_h3_edge_node(parts).await
}

/// Serves built [`ClusterParts`] over a freshly bound h3 listener with a
/// per-call self-signed cert, returned so a raw quinn client can pin it. The
/// edge only dials the mesh, so no mesh listener runs.
async fn boot_h3_edge_node(parts: ClusterParts) -> Result<(H3EdgeNode, UserKey)> {
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
    } = parts;
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
        0,
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

/// Establishes a session **against the home**, lets it park, and returns the id
/// the home minted for it.
///
/// Every SS relay case starts here now. With client crypto terminating on the
/// edge, the mesh carries one thing only: a session the home already holds. A
/// home with no park under the id refuses before the client is upgraded, and the
/// edge serves a fresh local session instead — so a test that wants the *relay*
/// exercised has to create the park first. Fabricating a plausible-looking id
/// (`resume_id_for_shard`) is no longer enough; that now tests the fallback.
///
/// `payload` is echoed by the target when non-empty, which is what proves the
/// upstream is live before it is parked.
async fn park_session_on_home(
    home: &ClusterNode,
    user: &UserKey,
    target: SocketAddr,
    payload: &[u8],
) -> Result<SessionId> {
    let (mut socket, issued) = connect_ws_h1(home.listen_addr, "/tcp", None, true).await?;
    let issued = issued.context("the home must mint a resume id for a resume-capable client")?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(user, target, payload)?))
        .await?;
    if !payload.is_empty() {
        let _ = expect_binary_reply(&mut socket).await?;
    }
    socket.close(None).await?;
    drop(socket);
    wait_for_park(home, issued).await?;
    Ok(issued)
}

/// Waits until `node` holds a park under `id`. The park lands when the carrier
/// ends, on the server's own schedule, so every case that resumes has to wait
/// for it rather than assume it.
async fn wait_for_park(node: &ClusterNode, id: SessionId) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !node.registry.has_park(id) {
        if tokio::time::Instant::now() >= deadline {
            bail!("the node never parked the session under {}", id.to_hex());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Survival across an edge switch: a session parked on its home is resumed
/// through one edge, then through a *different* edge, both relaying to that home
/// over the mesh. The home reuses the parked upstream throughout, so the echo
/// target sees exactly one accept across all three connects.
///
/// The first connect goes to the home directly because that is the only thing
/// that mints a park: with client crypto on the edge, the mesh carries only
/// sessions the home already owns. The second edge additionally proves the home
/// **re-parks** the upstream after the first relay ends — a session that
/// survived one switch and not the next would still pass a two-connect test.
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

    // Session #0 on the home itself: one upstream, parked under the id the home
    // minted. Both edges route that id back here over the mesh.
    let session_id = park_session_on_home(&home, &user, echo_addr, b"via-home").await?;
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the first session must open exactly one upstream"
    );

    // Session #1 via edge A: the edge authenticates the client itself and takes
    // the upstream over the mesh — the home's take_for_resume hits.
    let (mut sock_a, echoed_a) =
        connect_ws_h1(edge_a.listen_addr, "/tcp", Some(session_id), true).await?;
    assert_eq!(
        echoed_a,
        Some(session_id),
        "a relayed session must echo the id the home parks under",
    );
    sock_a
        .send(WsMessage::Binary(ss_handshake_frame(&user, echo_addr, b"via-edge-a")?))
        .await?;
    let _ = expect_binary_reply(&mut sock_a).await?;
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the relay must reuse the parked upstream (no fresh connect)"
    );
    sock_a.close(None).await?;
    drop(sock_a);
    // The home re-parks the upstream once the mesh carrier ends.
    wait_for_park(&home, session_id).await?;

    // Session #2 via edge B, same id: a second switch, still the same upstream.
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
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // The relay only carries a session the home holds, so park one there first.
    let session_id = park_session_on_home(&home, &user, echo_addr, b"warmup").await?;

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
    // Still the parked upstream: proof this went over the mesh rather than
    // degrading to a local session, which would echo just as faithfully.
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the payload must have crossed the mesh, not a fresh local upstream"
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

    let (echo_addr, echo_accepts) = spawn_echo_target().await?;
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(8), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(8), None, None).await?;

    // The relay only carries a session the home holds, so park one there first.
    let session_id = park_session_on_home(&home, &user, echo_addr, b"warmup").await?;

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
    // Still the parked upstream: proof the transfer crossed the mesh rather
    // than degrading to a local session.
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the transfer must have crossed the mesh, not a fresh local upstream"
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

    // Park the black hole on the home first — the relay only ever carries a
    // session the home holds, and it is the home's upstream that must stall.
    let session_id = park_session_on_home(&home, &user, blackhole, b"").await?;

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

    // The park is minted on the home over its own WS carrier; the h3 edge then
    // resumes it across transports, which is the cross-transport half of the
    // same guarantee.
    let session_id = park_session_on_home(&home, &user, echo_addr, b"via-home").await?;

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

    // The home owns the session and runs the mesh listener; the edge serves
    // `/ssx` and relays. The home no longer needs the `/ssx` route itself — with
    // client crypto on the edge it never authenticates this carrier — but it is
    // left configured so the case still covers a symmetric deployment.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), Some("/ssx"), None)
            .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) =
        spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), Some("/ssx"), None).await?;

    // Park the upstream on the home first (over its own WS carrier, with no
    // payload so the target's single 4-byte read is the relayed "ping"); the
    // XHTTP edge then resumes that id.
    let session_id = park_session_on_home(&home, &user, upstream_addr, b"").await?;
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

/// Adds the request-side advertisement of a client that speaks both resume
/// protocols and is resuming `parked`: Resume-Capable, the id itself,
/// Ack-Prefix (v1) and Symmetric Downlink Replay (v2). v2 is only ever active on
/// top of v1, so the pair always travels together.
fn with_v2_resume_headers(
    builder: axum::http::request::Builder,
    parked: SessionId,
) -> axum::http::request::Builder {
    builder
        .header(RESUME_CAPABLE_HEADER, "1")
        .header(RESUME_REQUEST_HEADER, parked.to_hex())
        .header(ACK_PREFIX_HEADER, "1")
        .header(SYMMETRIC_REPLAY_HEADER, "1")
}

/// Asserts an XHTTP response carries the echo of a session the edge really did
/// relay: continuity under the id the client presented, v1 confirmed, and v2
/// **withheld**.
///
/// The session-id check is what keeps the v2 check honest. A local fallback (no
/// relay opened, or a home that refused) echoes a freshly minted id, so a case
/// that quietly stopped exercising the relay fails here instead of passing on an
/// absent v2 header it never had a chance to emit.
fn assert_relayed_edge_echo(
    headers: &axum::http::HeaderMap,
    parked: SessionId,
    carrier: &str,
) -> Result<()> {
    let echoed = headers.get(SESSION_RESPONSE_HEADER).and_then(|v| v.to_str().ok());
    if echoed != Some(parked.to_hex().as_str()) {
        bail!(
            "{carrier}: expected the echo to continue the relayed session {}, got {echoed:?}",
            parked.to_hex(),
        );
    }
    if headers.get(ACK_PREFIX_HEADER).and_then(|v| v.to_str().ok()) != Some("1") {
        bail!("{carrier}: a relayed session must still confirm Ack-Prefix (v1)");
    }
    if headers.contains_key(SYMMETRIC_REPLAY_HEADER) {
        bail!(
            "{carrier}: the echo confirmed v2 Symmetric Downlink Replay, which a \
             mesh-relayed session cannot honour — the client would read the home's \
             undelimited plaintext replay suffix as an ORDR frame header and die",
        );
    }
    Ok(())
}

/// An XHTTP edge must never confirm a capability the mesh cannot honour.
///
/// On a relayed session the home's v2 replay suffix arrives as undelimited
/// plaintext at the head of the mesh body; the edge cannot wrap it in the framed
/// `ORDR` reply a v2 client expects, so the relayed echo withholds v2 (see
/// `mesh_relay::edge_upstream`). Answering from the request-derived negotiation
/// instead would tell a v2-capable client the protocol is active, and the client
/// would parse the replay suffix as a frame header and kill the session.
///
/// This pins all three axum entry points — packet-up GET, packet-up POST at
/// `seq = 0`, and stream-one POST over h2 — at the level the defect lived: the
/// response headers of a request that really did open a mesh relay. The edge has
/// v2 enabled in its own config, so the request-derived echo it *would* produce
/// differs from the relayed one; that is what gives the assertion teeth.
///
/// Each case needs its own park: a relay is opened per session-creating request,
/// and the home admits one only while it still holds the session.
#[tokio::test]
async fn cluster_xhttp_edge_echo_withholds_symmetric_replay() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-xhttp-echo-psk";
    let (echo_addr, _accepts) = spawn_echo_target().await?;

    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), Some("/ssx"), None)
            .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_xhttp_v2_node(PSK, 2, peers, Duration::from_secs(4), "/ssx").await?;
    let client = http_client();

    // 1. packet-up GET — the request that opens the downlink.
    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}/ssx/edge-echo-get", edge.listen_addr)),
        parked,
    )
    .body(Full::new(Bytes::new()))?;
    let response = client.request(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "the packet-up GET must be served");
    assert_relayed_edge_echo(response.headers(), parked, "packet-up GET")?;
    drop(response);

    // 2. packet-up POST at seq = 0 — the other shape that can create a session.
    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}/ssx/edge-echo-post", edge.listen_addr))
            .header("x-xhttp-seq", "0"),
        parked,
    )
    .body(Full::new(Bytes::new()))?;
    let response = client.request(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "the packet-up POST must be served");
    assert_relayed_edge_echo(response.headers(), parked, "packet-up POST seq=0")?;

    // 3. stream-one POST. Needs a real h2 connection (h1 cannot full-duplex, and
    // the handler answers 505 there), so handshake h2 directly over TCP as an
    // `xhttp_h2` client would.
    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let tcp = tokio::net::TcpStream::connect(edge.listen_addr).await?;
    let (mut send, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, BoxBody<Bytes, Infallible>>(TokioIo::new(tcp))
        .await?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    // Hold the uplink half open through the assertion: an immediate EOF would
    // race the relay into teardown while the response head is still in flight.
    let (frame_tx, frame_rx) =
        tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, Infallible>>(1);
    let uplink = BodyExt::boxed(StreamBody::new(futures_util::stream::unfold(
        frame_rx,
        |mut rx| async move { rx.recv().await.map(|frame| (frame, rx)) },
    )));
    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::POST)
            .uri(format!("http://{}/ssx/edge-echo-stream-one?mode=stream-one", edge.listen_addr))
            .header(header::HOST, edge.listen_addr.to_string()),
        parked,
    )
    .body(uplink)?;
    send.ready().await?;
    let response = send.send_request(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "the stream-one POST must be served");
    assert_relayed_edge_echo(response.headers(), parked, "stream-one POST")?;

    drop(frame_tx);
    connection_task.abort();
    Ok(())
}

/// The xhttp/h3 twin of [`cluster_xhttp_edge_echo_withholds_symmetric_replay`],
/// pinning the other three entry points: the h3 packet-up GET, the h3 packet-up
/// POST at `seq = 0`, and the h3 stream-one POST. Same invariant, same reason —
/// h3 has its own copy of the response-echo code, so it needs its own pin.
#[tokio::test]
async fn cluster_xhttp_h3_edge_echo_withholds_symmetric_replay() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-xhttp-h3-echo-psk";
    let (echo_addr, _accepts) = spawn_echo_target().await?;

    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), Some("/ssx"), None)
            .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) =
        spawn_xhttp_h3_v2_edge_node(PSK, 2, peers, Duration::from_secs(4), "/ssx").await?;

    let mut endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(test_h3_client_config(edge.cert_der.clone())?);
    let connection = endpoint.connect(edge.addr, "localhost")?.await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver_task =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let base = format!("https://localhost:{}/ssx", edge.addr.port());

    // 1. packet-up GET.
    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::GET)
            .uri(format!("{base}/edge-echo-h3-get"))
            .version(Version::HTTP_3),
        parked,
    )
    .body(())?;
    let mut req_stream = send_request.send_request(request).await?;
    req_stream.finish().await?;
    let response = req_stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK, "the xhttp/h3 GET must be served");
    assert_relayed_edge_echo(response.headers(), parked, "xhttp/h3 packet-up GET")?;
    drop(req_stream);

    // 2. packet-up POST at seq = 0. The handler drains the body to EOF before it
    // answers, so the request stream is finished right away.
    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::POST)
            .uri(format!("{base}/edge-echo-h3-post"))
            .version(Version::HTTP_3)
            .header("x-xhttp-seq", "0"),
        parked,
    )
    .body(())?;
    let mut req_stream = send_request.send_request(request).await?;
    req_stream.finish().await?;
    let response = req_stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK, "the xhttp/h3 POST must be served");
    assert_relayed_edge_echo(response.headers(), parked, "xhttp/h3 packet-up POST seq=0")?;
    drop(req_stream);

    // 3. stream-one POST: no seq, and the uplink half stays open (the carrier is
    // one bidirectional stream), so the response head is read on the live stream.
    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::POST)
            .uri(format!("{base}/edge-echo-h3-stream-one"))
            .version(Version::HTTP_3),
        parked,
    )
    .body(())?;
    let mut req_stream = send_request.send_request(request).await?;
    let response = req_stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK, "the xhttp/h3 stream-one must be served");
    assert_relayed_edge_echo(response.headers(), parked, "xhttp/h3 stream-one POST")?;

    driver_task.abort();
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

/// A relayed SS-UDP carrier whose home does not serve the edge's path must
/// degrade to a fresh local session on the edge, not disappear.
///
/// The home keys the relayed user lookup on the edge-supplied `header.path`, so
/// under an asymmetric cluster config that path resolves to an *empty* route
/// table — no configured key can authenticate a single datagram. This used to be
/// served anyway and every packet was silently dropped for the life of the
/// session (a black hole seen in production). The home now refuses such a stream
/// at setup with `CloseReason::NoRoute`, and because the edge waits for the
/// home's ack before upgrading the client carrier, it still has the choice to
/// serve the client itself — which is what this asserts: the echo comes back,
/// through the edge's own local session.
///
/// Only reachable under an asymmetric config; a symmetric cluster (matching
/// paths and users, the supported topology) always resolves the path, as
/// `cluster_udp_relays_datagrams_to_home` and `cluster_udp_xhttp_relays_to_home`
/// cover across the `udp` and `xhttp_ss_udp` tables respectively.
#[tokio::test]
async fn cluster_udp_relay_falls_back_locally_when_home_lacks_the_path() -> Result<()> {
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
        0,
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
    plaintext.extend_from_slice(b"not-into-the-void");
    socket
        .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
        .await?;

    // The home refused the relay for lack of a route, so the edge served this
    // carrier locally: the datagram reaches the target and the echo comes back.
    let reply = expect_binary_reply(&mut socket)
        .await
        .context("a relay the home refused must fall back to a local session, not be dropped")?;
    let decoded = decrypt_udp_packet(std::slice::from_ref(&user), &reply)?;
    assert!(
        decoded.payload.ends_with(b"not-into-the-void"),
        "the edge's local session must carry the datagram end to end",
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

/// Reads the first VLESS-UDP reply datagram's payload from the carrier,
/// tolerant of where WebSocket framing happens to land. VLESS rides a byte
/// stream: the relay queues the 2-byte VLESS response header
/// (`[VLESS_VERSION, 0x00]`) and each length-prefixed datagram
/// (`[len_be_hi, len_be_lo, payload…]`) as separate messages, but the transport
/// may deliver them as two binary frames or coalesce them into one — and on
/// resume the header may be replayed or omitted. A real client decodes the
/// stream and ignores frame boundaries; this helper does the same so the
/// assertion never hinges on framing timing.
///
/// The response header is recognized only as a *leading* `[VLESS_VERSION, 0x00]`;
/// a datagram length prefix of `[0, 0]` would mean an empty datagram, which these
/// tests never send, so the two never alias.
async fn read_vless_udp_datagram<S>(socket: &mut S) -> Result<Vec<u8>>
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    loop {
        // Drop an optional leading VLESS response header once it is fully present.
        if buf.len() >= 2 && buf[0] == VLESS_VERSION && buf[1] == 0x00 {
            buf.drain(..2);
        }
        // Return as soon as one whole length-prefixed datagram has arrived.
        if buf.len() >= 2 {
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() >= 2 + len {
                return Ok(buf[2..2 + len].to_vec());
            }
        }
        let frame = expect_binary_reply(socket).await?;
        buf.extend_from_slice(&frame);
    }
}

/// Establishes a VLESS-TCP session **against the home**, lets it park, and
/// returns the id the home minted for it.
///
/// The VLESS twin of [`park_session_on_home`], and needed for the same reason:
/// with client crypto terminating on the edge, the mesh carries only sessions
/// the home already holds, so a test that wants the relay exercised must create
/// the park first.
async fn park_vless_session_on_home(
    home: &ClusterNode,
    target: SocketAddr,
    payload: &[u8],
) -> Result<SessionId> {
    let (mut socket, issued) = connect_ws_h1(home.listen_addr, "/vless", None, true).await?;
    let issued = issued.context("the home must mint a resume id for a resume-capable client")?;
    socket
        .send(WsMessage::Binary(vless_tcp_request(CLUSTER_VLESS_UUID, target, payload)?))
        .await?;
    let echoed = read_vless_tcp_payload(&mut socket, payload.len()).await?;
    assert_eq!(echoed.as_slice(), payload, "the home's own VLESS session must reach the target");
    socket.close(None).await?;
    drop(socket);
    wait_for_park(home, issued).await?;
    Ok(issued)
}

/// Reads `want` bytes of VLESS-TCP payload off the carrier, skipping the leading
/// `[VLESS_VERSION, 0x00]` response header.
///
/// VLESS rides a byte stream: the header and the payload may arrive as one frame
/// or several, and a real client decodes the stream rather than the framing. The
/// header is stripped only when it leads, which is the one place it can appear.
async fn read_vless_tcp_payload<S>(socket: &mut S, want: usize) -> Result<Vec<u8>>
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut header_seen = false;
    loop {
        if !header_seen && buf.len() >= 2 {
            if buf[0] != VLESS_VERSION || buf[1] != 0x00 {
                bail!("expected a leading VLESS response header, got {:?}", &buf[..2]);
            }
            buf.drain(..2);
            header_seen = true;
        }
        if header_seen && buf.len() >= want {
            return Ok(buf);
        }
        let frame = expect_binary_reply(socket).await?;
        buf.extend_from_slice(&frame);
    }
}

/// Survival of a VLESS-TCP session across an edge switch, with the edge
/// terminating the client's VLESS layer and relaying plaintext to the home.
///
/// The VLESS counterpart of [`cluster_session_survives_edge_switch`], and the
/// direct replacement for the VLESS-UDP edge-switch coverage the v5 migration
/// gave up (see
/// [`cluster_vless_udp_park_on_the_home_survives_an_unrelayable_edge`]): for the
/// carrier shape that *is* migrated, the guarantee is now stronger, not weaker —
/// the same parked upstream is reused across two different edges, and the id the
/// client is told to come back with is the id the home parks under.
///
/// The first connect goes to the home directly because that is the only thing
/// that mints a park. The second edge additionally proves the home **re-parks**
/// the upstream after the first relay ends.
#[tokio::test]
async fn cluster_vless_tcp_survives_edge_switch() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-tcp-switch-psk";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    // Home owns shard 1; two edges (shards 2, 3) relay to it.
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge_a, _) =
        spawn_cluster_node(PSK, 2, peers.clone(), Duration::from_secs(4), None, None).await?;
    let (edge_b, _) = spawn_cluster_node(PSK, 3, peers, Duration::from_secs(4), None, None).await?;

    let session_id = park_vless_session_on_home(&home, echo_addr, b"via-home").await?;
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the first session must open exactly one upstream"
    );

    // Session #1 via edge A: the edge authenticates the VLESS UUID itself and
    // takes the upstream over the mesh — the home's take_for_resume hits.
    let (mut sock_a, echoed_a) =
        connect_ws_h1(edge_a.listen_addr, "/vless", Some(session_id), true).await?;
    assert_eq!(
        echoed_a,
        Some(session_id),
        "a relayed session must echo the id the home parks under",
    );
    sock_a
        .send(WsMessage::Binary(vless_tcp_request(
            CLUSTER_VLESS_UUID,
            echo_addr,
            b"via-edge-a",
        )?))
        .await?;
    let echoed = read_vless_tcp_payload(&mut sock_a, b"via-edge-a".len()).await?;
    assert_eq!(
        echoed.as_slice(),
        b"via-edge-a",
        "the relay must carry VLESS payload byte-exact"
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the relay must reuse the parked upstream (no fresh connect)"
    );
    sock_a.close(None).await?;
    drop(sock_a);
    // The home re-parks the upstream once the mesh carrier ends.
    wait_for_park(&home, session_id).await?;

    // Session #2 via edge B, same id: a second switch, still the same upstream.
    let (mut sock_b, echoed_b) =
        connect_ws_h1(edge_b.listen_addr, "/vless", Some(session_id), true).await?;
    assert_eq!(echoed_b, Some(session_id), "the second edge must echo the same parked id");
    sock_b
        .send(WsMessage::Binary(vless_tcp_request(
            CLUSTER_VLESS_UUID,
            echo_addr,
            b"via-edge-b",
        )?))
        .await?;
    let echoed = read_vless_tcp_payload(&mut sock_b, b"via-edge-b".len()).await?;
    assert_eq!(echoed.as_slice(), b"via-edge-b", "payload survives the second edge switch");
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "resume across the edge switch must reuse the parked upstream (no fresh connect)"
    );
    sock_b.close(None).await?;
    Ok(())
}

/// A relayed VLESS-TCP session hands the client the home's uplink offset, as the
/// Ack-Prefix v1 control frame the client already understands, ahead of every
/// relayed byte.
///
/// This is the one number that keeps a request body whole across a node switch:
/// the home counts what its upstream socket actually took and reports it over
/// the mesh ([`crate::server::cluster::mesh::UpstreamAckFrame`]), and the edge —
/// which owns the client's crypto now — re-emits it in the client's own
/// vocabulary. A client replaying from a wrong offset either duplicates or skips
/// part of its request, and neither is visible in a payload echo, so both halves
/// are asserted here: the value, and its position.
///
/// The position is asserted by parsing the byte stream in order. `"ORSM"` at
/// exactly the offset after the VLESS response header is what proves nothing
/// relayed was emitted first — a payload byte there would fail the parse rather
/// than be silently tolerated, which is precisely the failure mode the client
/// suffers.
#[tokio::test]
async fn cluster_vless_relayed_session_emits_the_homes_acked_offset_first() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-ackprefix-psk";
    // Written by the home's own session, so its upstream socket has taken these
    // bytes — and its `upstream_bytes_acked` is non-zero — by the time it parks.
    const VIA_HOME: &[u8] = b"seventeen-bytes!!";
    const VIA_EDGE: &[u8] = b"after-the-switch";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    let session_id = park_vless_session_on_home(&home, echo_addr, VIA_HOME).await?;

    // Resume through the edge as a v1-capable client: the advertisement is what
    // puts the frame on the wire at all.
    let (mut socket, echoed, ack_prefix_confirmed) =
        connect_ws_h1_ack_prefix(edge.listen_addr, "/vless", Some(session_id), true, true).await?;
    assert_eq!(echoed, Some(session_id), "the relayed session continues under the home's id");
    assert!(
        ack_prefix_confirmed,
        "a relayed session still confirms v1 — the edge re-emits the home's offset",
    );

    socket
        .send(WsMessage::Binary(vless_tcp_request(CLUSTER_VLESS_UUID, echo_addr, VIA_EDGE)?))
        .await?;

    // VLESS rides a byte stream, so read it as one: response header, then the
    // control frame, then the echoed payload — in that order, whatever the frame
    // boundaries turn out to be.
    let want = 2 + FRAME_LEN_V1 + VIA_EDGE.len();
    let mut stream: Vec<u8> = Vec::new();
    while stream.len() < want {
        let frame = expect_binary_reply(&mut socket).await?;
        stream.extend_from_slice(&frame);
    }
    assert_eq!(&stream[..2], &[VLESS_VERSION, 0x00], "the VLESS response header leads");
    match parse_v1(&stream[2..2 + FRAME_LEN_V1]) {
        ParseResult::Valid { up_acked } => assert_eq!(
            up_acked,
            VIA_HOME.len() as u64,
            "the edge must pass on the home's real upstream offset, not a fresh zero",
        ),
        other => bail!("expected an ack-prefix v1 frame right after the header, got {other:?}"),
    }
    assert_eq!(
        &stream[2 + FRAME_LEN_V1..want],
        VIA_EDGE,
        "the relayed payload follows the control frame",
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the offset is only meaningful if this really resumed the parked upstream",
    );

    socket.close(None).await?;
    Ok(())
}

/// A VLESS-UDP session presenting a foreign-shard resume id is served **locally**
/// by the edge, and still works.
///
/// **Assertion deliberately removed here:** the previous version of this test
/// (`cluster_vless_udp_relays_via_vless_tcp`) asserted the datagram travelled
/// edge→mesh→home→target, on the v4 rule that an edge forwards the still-
/// encrypted VLESS byte stream verbatim and the home parses the UDP command out
/// of it. Under v5 the edge terminates VLESS itself, so it sees
/// `VlessCommand::Udp` — a shape the home's plaintext splice does not carry
/// (`Parked::VlessUdpSingle`, not `Parked::Tcp`) — and serves the session from
/// this node instead. Relaying VLESS-UDP comes back when the home learns the
/// non-TCP park shapes; until then this test pins the fallback so the fallback
/// itself cannot rot: the datagram must still reach the target, and the echoed
/// id must be this edge's **own** freshly minted one, because this node has just
/// become the session's home. Echoing the presented id there would send the
/// client's next reconnect to a node that holds nothing.
#[tokio::test]
async fn cluster_vless_udp_foreign_shard_is_served_locally() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-udp-psk";
    let (target_addr, sources) = spawn_echo_udp_target().await?;

    // Home owns shard 1 (mesh listener); the edge (shard 2) can reach it. Both
    // register the shared VLESS user on `/vless` via `build_cluster_parts`.
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // Home-shard resume id the home holds nothing under: phase 1 refuses.
    let session_id = resume_id_for_shard(PSK, 1)?;
    let (mut socket, echoed_id) =
        connect_ws_h1(edge.listen_addr, "/vless", Some(session_id), true).await?;
    assert!(
        echoed_id.is_some() && echoed_id != Some(session_id),
        "a locally served session must echo this edge's own id, not the presented one",
    );

    socket
        .send(WsMessage::Binary(vless_udp_request(
            CLUSTER_VLESS_UUID,
            target_addr,
            b"vless-udp",
        )?))
        .await?;

    // The VLESS response header and the echoed length-prefixed datagram may
    // arrive as two binary frames or coalesced into one; read the stream.
    let echoed = read_vless_udp_datagram(&mut socket).await?;
    assert_eq!(
        echoed.as_slice(),
        b"vless-udp",
        "VLESS-UDP datagram relayed edge→target byte-exact",
    );
    assert_eq!(sources.lock().await.len(), 1, "the edge opens exactly one upstream source");

    socket.close(None).await?;
    Ok(())
}

/// A VLESS-UDP park on the home **survives** an edge that cannot relay it.
///
/// **Assertion deliberately removed here:** the previous version of this test
/// (`cluster_vless_udp_survives_edge_switch`) asserted that the target saw
/// exactly one upstream source across an edge switch — the home resuming its
/// parked `Arc<UdpSocket>` for a carrier that arrived on a different node. Under
/// v5 the edge terminates VLESS and finds a UDP command, whose upstream shape the
/// home's plaintext splice does not carry, so it serves the session locally on a
/// fresh source port. Cross-node VLESS-UDP migration therefore does not happen
/// while VLESS rides v5 and the home serves only `Parked::Tcp`; it returns when
/// the home learns the non-TCP park shapes.
///
/// What must hold in the meantime is the property that keeps that regression
/// *temporary* rather than destructive, and it is what this test now pins: the
/// home's park is neither consumed nor damaged by the edge that could not use
/// it. Two independent barriers are exercised at once — the home's phase-1
/// `probe_park` answering `ParkProbe::OtherShape` for a UDP-shaped park, before
/// anything is taken, and the edge releasing the relay the moment it reads a
/// non-TCP command. A regression
/// in either would show up as the third connect binding a *third* source port,
/// because the park would have been destroyed by the second.
#[tokio::test]
async fn cluster_vless_udp_park_on_the_home_survives_an_unrelayable_edge() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-udp-switch-psk";
    let (target_addr, sources) = spawn_echo_udp_target().await?;

    // Home owns shard 1; the edge (shard 2) can relay to it.
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // Session #1 on the home itself: one UDP source, parked as
    // `Parked::VlessUdpSingle` under the id the home minted.
    let (mut sock_home, issued) = connect_ws_h1(home.listen_addr, "/vless", None, true).await?;
    let session_id = issued.context("the home must mint a resume id")?;
    sock_home
        .send(WsMessage::Binary(vless_udp_request(
            CLUSTER_VLESS_UUID,
            target_addr,
            b"vless-home",
        )?))
        .await?;
    let echoed = read_vless_udp_datagram(&mut sock_home).await?;
    assert_eq!(echoed.as_slice(), b"vless-home", "the home's own session reaches the target");
    assert_eq!(sources.lock().await.len(), 1, "the first session binds exactly one source");
    sock_home.close(None).await?;
    drop(sock_home);
    wait_for_park(&home, session_id).await?;

    // Session #2 via the edge, same id. The home refuses in phase 1 because the
    // park is not TCP-shaped, so the edge mints its own id and serves the
    // session locally — on a second source port.
    let (mut sock_edge, echoed_id) =
        connect_ws_h1(edge.listen_addr, "/vless", Some(session_id), true).await?;
    assert!(
        echoed_id.is_some() && echoed_id != Some(session_id),
        "an edge that could not relay must echo its own id, not the presented one",
    );
    sock_edge
        .send(WsMessage::Binary(vless_udp_request(
            CLUSTER_VLESS_UUID,
            target_addr,
            b"vless-edge",
        )?))
        .await?;
    let echoed = read_vless_udp_datagram(&mut sock_edge).await?;
    assert_eq!(
        echoed.as_slice(),
        b"vless-edge",
        "the locally served session reaches the target"
    );
    assert_eq!(
        sources.lock().await.len(),
        2,
        "a locally served VLESS-UDP session binds its own source (the removed guarantee)",
    );
    sock_edge.close(None).await?;
    drop(sock_edge);

    // The home's park must still be there, untouched by the edge that could not
    // use it.
    assert!(
        home.registry.has_park(session_id),
        "the edge must not consume a park it cannot splice",
    );

    // And it must still be *usable*: resuming it directly on the home reattaches
    // the same socket rather than binding a third one.
    let (mut sock_back, _) =
        connect_ws_h1(home.listen_addr, "/vless", Some(session_id), true).await?;
    sock_back
        .send(WsMessage::Binary(vless_udp_request(
            CLUSTER_VLESS_UUID,
            target_addr,
            b"vless-back",
        )?))
        .await?;
    let echoed = read_vless_udp_datagram(&mut sock_back).await?;
    assert_eq!(echoed.as_slice(), b"vless-back", "the surviving park still carries datagrams");
    assert_eq!(
        sources.lock().await.len(),
        2,
        "resuming the surviving park must reuse its socket, not bind a third source",
    );
    sock_back.close(None).await?;
    Ok(())
}

/// A VLESS-**TCP** command presenting an id the home parked as **VLESS-UDP** must
/// not cost the home that park.
///
/// This is the case the home's phase-1 shape check exists for, and the only one
/// where the edge's own release cannot help: the edge reads `VlessCommand::Tcp`,
/// which is exactly the shape a mesh upstream carries, so it goes on to send the
/// USER frame — and the USER frame is what makes the home call `take_for_resume`.
/// A phase 1 that admitted any shape would hand the park over and *then* discover
/// it is not `Parked::Tcp`, refusing with the park already consumed.
///
/// Cross-shape id reuse is a client that dialled TCP on a carrier whose previous
/// incarnation was UDP or mux — VLESS multiplexes all three onto one path, so
/// the id alone cannot say which. Asking the shape question in phase 1 turns
/// that from a destroyed session into an ordinary local fallback.
#[tokio::test]
async fn cluster_vless_tcp_on_a_udp_shaped_park_leaves_it_intact() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-crossshape-psk";
    let (udp_addr, udp_sources) = spawn_echo_udp_target().await?;
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // Park a VLESS-UDP session on the home: `Parked::VlessUdpSingle`.
    let (mut sock_home, issued) = connect_ws_h1(home.listen_addr, "/vless", None, true).await?;
    let session_id = issued.context("the home must mint a resume id")?;
    sock_home
        .send(WsMessage::Binary(vless_udp_request(CLUSTER_VLESS_UUID, udp_addr, b"udp-home")?))
        .await?;
    let echoed = read_vless_udp_datagram(&mut sock_home).await?;
    assert_eq!(echoed.as_slice(), b"udp-home");
    sock_home.close(None).await?;
    drop(sock_home);
    wait_for_park(&home, session_id).await?;

    // Same id, TCP command, through the edge. The home refuses in phase 1
    // *before* consuming anything, so this is served locally and works.
    let (mut socket, echoed_id) =
        connect_ws_h1(edge.listen_addr, "/vless", Some(session_id), true).await?;
    assert!(
        echoed_id.is_some() && echoed_id != Some(session_id),
        "the home holds no TCP-shaped park, so the edge must mint and echo its own id",
    );
    socket
        .send(WsMessage::Binary(vless_tcp_request(
            CLUSTER_VLESS_UUID,
            echo_addr,
            b"tcp-edge",
        )?))
        .await?;
    let echoed = read_vless_tcp_payload(&mut socket, b"tcp-edge".len()).await?;
    assert_eq!(echoed.as_slice(), b"tcp-edge", "the locally served TCP session must work");
    assert_eq!(echo_accepts.load(Ordering::SeqCst), 1, "the edge dials its own TCP upstream");
    socket.close(None).await?;
    drop(socket);

    // The UDP park must still be on the home, and still usable: resuming it
    // reattaches the same socket rather than binding a second one.
    assert!(
        home.registry.has_park(session_id),
        "a TCP command must not consume a UDP-shaped park on the home",
    );
    let (mut sock_back, _) =
        connect_ws_h1(home.listen_addr, "/vless", Some(session_id), true).await?;
    sock_back
        .send(WsMessage::Binary(vless_udp_request(CLUSTER_VLESS_UUID, udp_addr, b"udp-back")?))
        .await?;
    let echoed = read_vless_udp_datagram(&mut sock_back).await?;
    assert_eq!(echoed.as_slice(), b"udp-back", "the surviving park still carries datagrams");
    assert_eq!(
        udp_sources.lock().await.len(),
        1,
        "resuming the surviving park must reuse its socket, not bind a second source",
    );
    sock_back.close(None).await?;
    Ok(())
}

/// A VLESS **mux** command releases a mesh relay the edge had already opened,
/// serves its sub-connections directly, and leaves the home's park intact.
///
/// This is the edge-side half of the same invariant the test above pins from the
/// home side, and the only place it can be exercised: the home holds a
/// `Parked::Tcp` here, so phase 1 legitimately admits the relay and the edge
/// really does take a mesh upstream before it can know what the client wants.
/// Only when the first frame parses as `VlessCommand::Mux` does it learn that
/// the upstream shape is wrong — and it must get out *before* the USER frame,
/// which is what would make the home consume its park.
///
/// It also pins the scope decision that VLESS-mux sub-connections stay on the
/// direct path: the sub-connection below reaches its target from the edge, on a
/// socket the edge dialled itself.
///
/// Finally it pins the *echo*, which is deliberately not truthful here and
/// cannot be made so: the `101` goes out before the edge has read a single
/// client byte, so at the moment it is written the relay is still admitted and
/// the only correct id to echo is the home's. Only the first VLESS frame reveals
/// the mux command, and by then the id is on the wire. The cost is bounded and
/// non-destructive — the client comes back with the home's id, the home still
/// holds that park, and the edge serves it locally again — where the two
/// alternatives are worse: withholding the id from every VLESS upgrade would
/// give up continuity for the TCP command this whole path exists for, and
/// delaying the `101` until the first frame would break the upgrade handshake
/// itself. The session served here is simply not resumable (`edge_upstream`
/// leaves `issued_session_id` unset, so nothing parks locally either).
#[tokio::test]
async fn cluster_vless_mux_releases_the_relay_and_preserves_the_park() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-mux-release-psk";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // A TCP-shaped park on the home, so the edge's phase-1 OPEN is admitted.
    let session_id = park_vless_session_on_home(&home, echo_addr, b"via-home").await?;
    assert_eq!(echo_accepts.load(Ordering::SeqCst), 1, "one upstream so far");

    // Same id, but a mux command: the edge must release the relay and serve the
    // mux locally.
    let (mut socket, echoed_id) =
        connect_ws_h1(edge.listen_addr, "/vless", Some(session_id), true).await?;
    // Deliberate, and documented above: the echo was written while the relay was
    // still admitted, so it names the home's id even though this session ends up
    // served locally and parks nothing. Pinned rather than left unasserted, so a
    // future change to the echo is a decision and not a surprise.
    assert_eq!(
        echoed_id,
        Some(session_id),
        "an admitted relay echoes the home's id, even on the path that later releases it",
    );
    socket
        .send(WsMessage::Binary(vless_mux_request(CLUSTER_VLESS_UUID)?))
        .await?;
    socket
        .send(WsMessage::Binary(vless_mux_new_tcp_frame(1, echo_addr, b"mux-sub")))
        .await?;
    // The mux session answers with the standard VLESS response header as its own
    // message, ahead of any mux frame.
    let response_header = expect_binary_reply(&mut socket).await?;
    assert_eq!(response_header.as_ref(), &[VLESS_VERSION, 0x00]);
    let payloads = collect_mux_keep_payloads(&mut socket, &[1]).await?;
    assert_eq!(
        payloads.get(&1).map(Vec::as_slice),
        Some(b"mux-sub".as_slice()),
        "a mux sub-connection must reach its target from the edge itself",
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        2,
        "the sub-connection dials its own upstream (mux stays on the direct path)",
    );
    socket.close(None).await?;
    drop(socket);

    // The park the edge could not use must still be on the home.
    assert!(
        home.registry.has_park(session_id),
        "a mux command must not cost the home the park it was holding",
    );
    Ok(())
}

/// Throttle detection on a relayed SS-TCP session, end to end. With padding +
/// throttle detection enabled on a dedicated path, a client that stalls its
/// downlink read while the home floods it through the mesh makes the edge's
/// client-facing send block; the edge detects the stall and injects an `OCTL`
/// cover frame, which the client decodes as `ThrottleSwitchUplink`.
///
/// The detection is **local to the edge** here, and no `THROTTLE_HINT` datagram
/// is involved: with client crypto terminating on the edge, the node that owns
/// the throttled last mile is also the node that owns the padded writer, so it
/// signals its own client directly. The mesh hint mechanism still serves the
/// carriers whose edge relays ciphertext (VLESS, SS-UDP), and keeps its own
/// coverage in `transport::mesh_relay`'s tests.
///
/// Padding is a process-global; it is scoped to this test's own path so the
/// other cluster tests' `/tcp` carriers stay unpadded (and nothing else in the
/// test binary calls `carrier_padding::init`).
///
/// `#[ignore]`d in CI, and **currently red even when run manually**: firing a
/// detector needs the socket buffers between home→mesh→edge→client to be *full*
/// within the stall, which depends on OS TCP buffer autotuning the test cannot
/// size. It was already timing-dependent when the edge relayed ciphertext and
/// signalled over the mesh; with SS-TCP now detecting locally, the window that
/// has to trip is the rate-based one (`window_is_throttled`), whose inbound side
/// is the *mesh* rather than the internet — so the tunables above need
/// re-deriving before this can be relied on. Left in place, retargeted and
/// honestly labelled rather than deleted: the wire path it walks is real.
///
/// The pieces are covered deterministically elsewhere: the mesh hint itself
/// (still used by the VLESS / SS-UDP edges) by `mesh_relay`'s
/// `edge_detector_signals_throttle_hint_over_the_mesh` plus the `StallTracker`
/// unit tests, the rate-based window by the `throughput_monitor` tests, and the
/// signal→OCTL half by the `ThrottleRegistry` and `ws_writer` tests.
#[tokio::test]
#[ignore = "known-red: throttle tunables need re-deriving for edge-local detection (see doc)"]
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

    // Park the flood target on the home so the edge really relays this session
    // rather than degrading to a local one.
    let (mut warmup, issued) = connect_ws_h1(home.listen_addr, PATH, None, true).await?;
    let session_id = issued.context("the home must mint a resume id")?;
    let ss_warmup = ss_handshake_frame(&user, flood_addr, b"warmup")?;
    let mut framed_warmup = Vec::new();
    encode_frame_into(&mut framed_warmup, &ss_warmup, &[]).expect("padding frame within bounds");
    warmup.send(WsMessage::Binary(framed_warmup.into())).await?;
    let _ = expect_binary_reply(&mut warmup).await?;
    warmup.close(None).await?;
    drop(warmup);
    wait_for_park(&home, session_id).await?;

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
        "client must decode an OCTL ThrottleSwitchUplink cover frame injected on the edge \
         after it detected the throttled client segment (got {got_octl:?})",
    );
    Ok(())
}
