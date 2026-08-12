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
//! and whichever node it lands on decrypts successfully, whether that node
//! serves the session itself or relays the resulting plaintext to the home.
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
use bytes::{BufMut, Bytes, BytesMut};
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
use super::super::super::resumption::{
    OrphanRegistry, Parked, ParkedVlessMux, ResumptionConfig, SessionId,
};
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
    collect_mux_keep_payloads, collect_streamed_mux_keep_payloads, vless_mux_keep_frame,
    vless_mux_new_tcp_frame, vless_mux_new_udp_frame, vless_mux_request, vless_tcp_request,
    vless_udp_request,
};
use super::{
    connect_ws_h1, connect_ws_h1_ack_prefix, connect_ws_h1_symmetric_replay, expect_binary_reply,
    read_ss_plaintext, spawn_delayed_echo_udp_target, spawn_echo_target, spawn_echo_udp_target,
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

/// A *second* VLESS UUID, for the edge in the cross-node VLESS-UDP test. The
/// edge authenticates its client against this one while the home's park was
/// minted under [`CLUSTER_VLESS_UUID`] — which only works because the mesh
/// carries VLESS payload, not the VLESS handshake.
const EDGE_VLESS_UUID: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

/// `downlink_buffer_bytes` for the nodes that must have v2 Symmetric Downlink
/// Replay enabled in their own resumption config. Any non-zero value flips
/// `OrphanRegistry::symmetric_replay_enabled`; the size itself is irrelevant to
/// these tests, which never fill the ring.
const V2_DOWNLINK_BUFFER_BYTES: usize = 64 * 1024;

/// Base64 of a 16-byte PSK — the password shape an SS-2022 cipher requires,
/// where the legacy ciphers take any string. Used by the nodes and clients that
/// need real SS-2022 UDP responses (see `build_cluster_parts`).
const SS2022_PSK: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";

/// A running cluster node: an SS-over-WS listener plus a mesh endpoint (home
/// listener + edge dialer). Aborts its tasks on drop so tests don't leak
/// listeners between cases.
struct ClusterNode {
    listen_addr: SocketAddr,
    mesh_addr: SocketAddr,
    /// This node's park registry, so a test can wait for a session to land
    /// rather than sleeping for it.
    registry: Arc<OrphanRegistry>,
    /// This node's metrics handle. Each node builds its own recorder, so a
    /// rendered scrape here names only what *this* node counted — which is what
    /// lets a test assert a home's refusal reason without the edge's series
    /// bleeding into it.
    metrics: Arc<Metrics>,
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
    ss_password: Option<&str>,
    ws_ss_path: Option<&str>,
    downlink_buffer_bytes: usize,
    ss2022: bool,
    // `(ws path, UUID, accounting label)` for this node's VLESS route.
    vless_route: Option<(&str, &str, &str)>,
) -> Result<ClusterParts> {
    // The mesh QUIC endpoint needs the process-wide rustls provider installed.
    ensure_rustls_provider_installed();

    let mut config = sample_config((Ipv4Addr::LOCALHOST, 0).into());
    // SS-2022 changes what a UDP *response* carries: the server session id the
    // NAT entry allocated, plus a per-session packet counter. The legacy cipher
    // has no field for either, so only a 2022 node can tell whether that id was
    // reserved at all — which is what the direct/relayed hand-off depends on.
    if ss2022 {
        config.method = CipherKind::Aes128Gcm2022;
        config.users[0].password = Some(SS2022_PSK.to_string());
    }
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
    // A per-node SS password. Deliberately *not* the user label, which stays
    // "bob" on every node: the label is the park's owner and the home checks it
    // against the name the edge attests, so it must denote the same person
    // cluster-wide. The secret behind it is the node's own — that is the shape a
    // real cluster has, and the one the v5 relay exists to survive, because the
    // client's crypto terminates on whichever node it lands on.
    if let Some(password) = ss_password {
        config.users[0].password = Some(password.to_string());
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
    //
    // `vless_route` overrides the *path, UUID and accounting label* for one
    // node. The first two are how a test proves the mesh carries VLESS payload
    // rather than the VLESS handshake: each node authenticates its client
    // against its own credentials. The label is the park's **owner**, and the
    // home checks it against the name the edge attests, so it must denote the
    // same person cluster-wide — every VLESS-only case leaves it at the default.
    // A cross-protocol case overrides it to the SS user's own label, which is
    // what one `[[users]]` entry carrying both `password` and `vless_id` looks
    // like in production.
    let (vless_path, vless_uuid, vless_label) =
        vless_route.unwrap_or(("/vless", CLUSTER_VLESS_UUID, "cluster-vless"));
    let vless = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: VlessUser::new(vless_uuid.into(), Arc::from(vless_label), None, None)?,
        ws_path: Arc::from(vless_path),
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
            replay_store: ReplayStore::new(Duration::from_secs(300), 0, 0),
            relay_semaphore: None,
        },
        Some(orphan_registry),
        16,
        crate::server::transport::XhttpRegistryLimits::unbounded(),
        crate::server::salt_replay::SaltReplayStore::new(std::time::Duration::from_secs(60), 0),
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
        None,
        0,
        false,
        None,
    )?;
    boot_ws_node(parts).await
}

/// Boots a WS cluster node whose VLESS route is its **own**: a different path
/// and a different UUID from every other node's.
///
/// That is the shape a real cluster has — each node authenticates its clients
/// against its own credentials — and the only way to prove the mesh carries
/// VLESS *payload* rather than the VLESS handshake: a session parked on one
/// node's UUID resumes through an edge that has never heard of it. The user
/// label is deliberately *not* overridden: it is the park's owner, and the home
/// checks the name the edge attests against it.
async fn spawn_vless_cluster_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    vless_path: &str,
    vless_uuid: &str,
) -> Result<(ClusterNode, UserKey)> {
    let parts = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        None,
        None,
        None,
        None,
        None,
        0,
        false,
        Some((vless_path, vless_uuid, "cluster-vless")),
    )?;
    boot_ws_node(parts).await
}

/// Boots a WS cluster node serving **one account over both proxy protocols**:
/// the SS user `"bob"` on `/tcp` and a VLESS route on `/vless` whose accounting
/// label is also `"bob"`.
///
/// That is the fleet's own shape — a single `[[users]]` entry carries both
/// `password` and `vless_id`, and both wires park under that entry's `id` — and
/// it is the only way to reach the cross-protocol splice end to end: the home's
/// owner check runs on the label, so SS and VLESS must agree on it or the relay
/// is refused as `unknown_user` before the protocol question is ever asked.
async fn spawn_dual_protocol_cluster_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
) -> Result<(ClusterNode, UserKey)> {
    let parts = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        None,
        None,
        None,
        None,
        None,
        0,
        false,
        Some(("/vless", CLUSTER_VLESS_UUID, "bob")),
    )?;
    boot_ws_node(parts).await
}

/// Boots a WS cluster node whose **SS** carrier is its own: its own path and its
/// own per-user password, sharing only the user *label* with the rest of the
/// cluster.
///
/// This is the topology that was broken in production — every node with its own
/// paths and its own secrets — and the SS counterpart of
/// [`spawn_vless_cluster_node`]. Under v5 it is servable because the node the
/// client lands on terminates the client's crypto and the mesh carries
/// plaintext: the home never sees the edge's key, and the only identity crossing
/// the mesh is the user name the edge attests.
///
/// `downlink_buffer_bytes` is per node because v2 Symmetric Downlink Replay is
/// asymmetric across a relay: only the *home* needs a ring (it is the one that
/// replays the unacked suffix onto the mesh), while the edge forwards the
/// client's raw advertisement regardless of its own config.
async fn spawn_asymmetric_ss_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
    ss_tcp_path: &str,
    ss_password: &str,
    downlink_buffer_bytes: usize,
) -> Result<(ClusterNode, UserKey)> {
    let parts = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        None,
        None,
        Some(ss_tcp_path),
        Some(ss_password),
        None,
        downlink_buffer_bytes,
        false,
        None,
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
    let metrics = Arc::clone(&cluster.metrics);
    let ws_task =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });
    let mesh_task = tokio::spawn(run_mesh_listener(cluster, services, ShutdownSignal::never()));

    Ok((
        ClusterNode {
            listen_addr,
            mesh_addr,
            registry,
            metrics,
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
        None,
        V2_DOWNLINK_BUFFER_BYTES,
        false,
        None,
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
    let parts = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        None,
        None,
        None,
        None,
        Some(ws_ss_path),
        0,
        false,
        None,
    )?;
    boot_ws_node(parts).await
}

/// Boots a WS cluster node whose shared user runs an **SS-2022** cipher.
///
/// The direct↔relayed hand-off tests need one: on the legacy cipher a UDP
/// response carries no server session id, so
/// [`crate::crypto::encrypt_udp_packet_for_response`] ignores the one the NAT
/// entry holds and the whole `ServerSessionId::for_coding` question is invisible.
/// On SS-2022 the seal *requires* it, so a NAT socket that changes hands between
/// a relayed carrier and a direct one only keeps answering if the id was
/// reserved when the entry was created.
async fn spawn_ss2022_node(
    psk: &[u8],
    shard: u8,
    peers: HashMap<ShardId, SocketAddr>,
    budget: Duration,
) -> Result<(ClusterNode, UserKey)> {
    let parts = build_cluster_parts(
        psk, shard, peers, budget, None, None, None, None, None, 0, true, None,
    )?;
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
    let parts = build_cluster_parts(
        psk,
        shard,
        peers,
        budget,
        None,
        None,
        Some(ss_tcp_path),
        None,
        None,
        0,
        false,
        None,
    )?;
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
    let parts = build_cluster_parts(
        psk, shard, peers, budget, None, None, None, None, None, 0, false, None,
    )?;
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
        None,
        V2_DOWNLINK_BUFFER_BYTES,
        false,
        None,
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
    /// The node's orphan registry, so a test can assert what it parked — the h3
    /// node has no `ClusterNode` to reach it through.
    registry: Arc<OrphanRegistry>,
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
        None,
        0,
        false,
        None,
    )?;
    let registry = Arc::clone(&services.orphan_registry);
    let ctx = H3ServeCtx {
        routes,
        services,
        auth,
        alpn: Arc::from(vec![H3Alpn::H3].into_boxed_slice()),
        http_fallback: None,
        cluster: Some(cluster),
    };
    let h3_task = tokio::spawn(serve_h3_server(server, ctx, ShutdownSignal::never()));

    Ok((H3ClientNode { addr, registry, h3_task }, user))
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
    park_session_on_home_path(home, "/tcp", user, target, payload).await
}

/// [`park_session_on_home`] against a home that serves SS somewhere other than
/// the default `/tcp` — the asymmetric-cluster cases, where every node has its
/// own carrier path.
async fn park_session_on_home_path(
    home: &ClusterNode,
    path: &str,
    user: &UserKey,
    target: SocketAddr,
    payload: &[u8],
) -> Result<SessionId> {
    let (mut socket, issued) = connect_ws_h1(home.listen_addr, path, None, true).await?;
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

/// Establishes an **SS-UDP** session against the home, round-trips one datagram
/// so the NAT entry is real, lets it park, and returns the id the home minted.
///
/// The SS-UDP twin of [`park_session_on_home`], and needed for the same reason:
/// with client crypto terminating on the edge, a v5 relay carries only a session
/// the home already holds. A home with no park under the presented id refuses
/// before the client is upgraded, and the edge serves a fresh local session — so
/// a test that wants the *relay* exercised has to create the park first, and a
/// fabricated `resume_id_for_shard` now tests the fallback instead.
async fn park_udp_session_on_home(
    home: &ClusterNode,
    path: &str,
    user: &UserKey,
    target: SocketAddr,
    payload: &[u8],
) -> Result<SessionId> {
    let (mut socket, issued) = connect_ws_h1(home.listen_addr, path, None, true).await?;
    let issued = issued.context("the home must mint a resume id for a resume-capable client")?;
    let mut plaintext = TargetAddr::from(target).to_wire_bytes()?;
    plaintext.extend_from_slice(payload);
    socket
        .send(WsMessage::Binary(encrypt_udp_packet(user, &plaintext)?.into()))
        .await?;
    let _ = expect_binary_reply(&mut socket).await?;
    socket.close(None).await?;
    drop(socket);
    wait_for_park(home, issued).await?;
    Ok(issued)
}

/// The [`UdpWsTransport`] twin of [`park_udp_session_on_home`], for the homes
/// whose SS-UDP leg the raw WS helper cannot dial — a combined-SS base, whose
/// `/{token}` UDP discriminator only the real client encodes.
#[allow(clippy::too_many_arguments)]
async fn park_udp_client_session_on_home(
    home: &ClusterNode,
    url: &Url,
    mode: TransportMode,
    cipher: CipherKind,
    password: &str,
    kind: Option<SsPathKind>,
    tag: &'static str,
    target: SocketAddr,
) -> Result<ClientSessionId> {
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let (transport, issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache, url, mode, cipher, password, None, false, tag, None, None, kind,
    )
    .await?;
    let issued = issued.context("a resume-capable dial must be issued a session id")?;
    transport.send_packet(&ss_first_chunk(target, b"seed")).await?;
    let reply = transport.read_packet().await?;
    anyhow::ensure!(reply.ends_with(b"seed"), "the home must serve the seeding datagram itself");
    transport.close().await?;
    wait_for_park(home, SessionId::from_bytes(*issued.as_bytes())).await?;
    Ok(issued)
}

/// Waits until `node` holds a park under `id`. The park lands when the carrier
/// ends, on the server's own schedule, so every case that resumes has to wait
/// for it rather than assume it.
async fn wait_for_park(node: &ClusterNode, id: SessionId) -> Result<()> {
    wait_for_park_in(&node.registry, id).await
}

/// [`wait_for_park`] against a bare registry, for the h3 node (which has no
/// `ClusterNode` wrapper).
async fn wait_for_park_in(registry: &OrphanRegistry, id: SessionId) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !registry.has_park(id) {
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

    // Traffic, not hand-offs. The home records `hit` the moment a splice ends,
    // however it ended, so a relay whose park is handed over and whose splice
    // then carries nothing reads on the outcome counters exactly like a working
    // one — the shape a production regression took while every hand-off
    // assertion above stayed green. Both directions, because a relay that only
    // ever carries uplink is equally broken and equally invisible.
    let rendered = home.metrics.render_prometheus();
    assert!(
        mesh_bytes(&rendered, "up") >= b"via-edge-a".len() as u64 + b"via-edge-b".len() as u64,
        "both switches must have carried their request across the splice: {rendered}",
    );
    assert!(
        mesh_bytes(&rendered, "down") >= b"via-edge-a".len() as u64 + b"via-edge-b".len() as u64,
        "both switches must have carried the target's answer back: {rendered}",
    );

    sock_b.close(None).await?;
    Ok(())
}

// ── Cross-node continuity on an asymmetric cluster ────────────────────────────

/// The SS carrier path and per-user secret of the node that mints the park, and
/// of the node the session then moves to. Nothing is shared but the user label
/// — the topology the owner's fleet actually runs, and the one the v4 relay
/// turned into a black hole.
const HOME_SS_PATH: &str = "/home-only-path/ss";
const EDGE_SS_PATH: &str = "/edge-only-path/ss";
const HOME_SS_SECRET: &str = "home-only-secret";
const EDGE_SS_SECRET: &str = "edge-only-secret";

/// [`read_ss_plaintext`] against a **padded** carrier: strips the carrier-padding
/// framing before the AEAD layer, which is exactly the order a padding-enabled
/// client decodes in (`outline_transport`'s reader feeds its `PaddingDecoder`
/// first and the Shadowsocks stream second).
///
/// The distinction matters because padding is config-synchronised with no
/// on-wire capability bit: on a padded path *every* downlink WebSocket message
/// is a padding frame, so a single unpadded message does not merely arrive
/// unwrapped — it is consumed as padding framing and corrupts the AEAD stream
/// behind it.
async fn read_padded_ss_plaintext<S>(socket: &mut S, user: &UserKey, want: usize) -> Result<Vec<u8>>
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let mut decoder = PaddingDecoder::new();
    let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user.clone()].into_boxed_slice()));
    let mut plaintext = Vec::new();
    let mut ciphertext = Vec::new();
    while plaintext.len() < want {
        let frame = expect_binary_reply(socket).await?;
        ciphertext.clear();
        decoder.push(&frame, &mut ciphertext);
        // A pad-only frame carries no payload; keep reading.
        if ciphertext.is_empty() {
            continue;
        }
        decryptor.feed_ciphertext(&ciphertext);
        decryptor.drain_plaintext(&mut plaintext)?;
    }
    Ok(plaintext)
}

/// A relayed SS resume on a **padded** carrier: the Ack-Prefix control frame has
/// to be padded like every other downlink message, or the client cannot read it.
///
/// This is the fleet's own configuration — `padding = true` on every uplink — and
/// the one the whole Ack-Prefix suite misses: the five other `ack_prefix` cases
/// all dial unpadded carriers, where a frame that skips the padding writer is
/// indistinguishable from one that does not.
///
/// The failure it pins is silent and total. Padding carries no capability bit, so
/// a client on a padded path feeds *every* downlink message to its
/// `PaddingDecoder`; an unpadded 14-byte control frame is therefore not read as a
/// bare frame but eaten as framing, and the AEAD stream behind it desynchronises.
/// The client reports `aes-256-gcm decryption failed`, treats it as a resume miss
/// and resets the flow — so a soft switch migrates nothing at all while the home
/// happily records a hit and hands over the park. Observed on the fleet as
/// `orphan_resume_hit_total` climbing against `mesh_bytes_total{transport="tcp"}`
/// flat at zero.
///
/// VLESS never had this: its resume path already routes the same frame through
/// `carrier_padding::frame_downlink_message`, which is why a padded fleet's
/// VLESS-carried migrations kept working while its SS-carried ones did not.
#[tokio::test]
async fn cluster_relayed_ss_ack_prefix_is_carrier_padded() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-ss-ack-prefix-padding";
    const VIA_HOME: &[u8] = b"seventeen-bytes!!";
    const VIA_EDGE: &[u8] = b"after-the-switch";
    enable_combined_padding_globals();
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    let (home, user) =
        spawn_throttle_node(PSK, 1, HashMap::new(), Duration::from_secs(4), SS_TCP_PADDED_PATH)
            .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, edge_user) =
        spawn_throttle_node(PSK, 2, peers, Duration::from_secs(4), SS_TCP_PADDED_PATH).await?;

    // Park on the home. The uplink pads too, so the handshake rides inside one
    // padding frame (an empty pad is a valid frame).
    let (mut warmup, issued) =
        connect_ws_h1(home.listen_addr, SS_TCP_PADDED_PATH, None, true).await?;
    let session_id = issued.context("the home must mint a resume id")?;
    let mut framed = Vec::new();
    encode_frame_into(&mut framed, &ss_handshake_frame(&user, echo_addr, VIA_HOME)?, &[])
        .expect("padding frame within u16 bounds");
    warmup.send(WsMessage::Binary(framed.into())).await?;
    let _ = expect_binary_reply(&mut warmup).await?;
    warmup.close(None).await?;
    drop(warmup);
    wait_for_park(&home, session_id).await?;

    // Resume through the edge, which relays to the home and owes this client the
    // home's upstream offset as an Ack-Prefix frame.
    let (mut socket, echoed, ack_prefix_confirmed) = connect_ws_h1_ack_prefix(
        edge.listen_addr,
        SS_TCP_PADDED_PATH,
        Some(session_id),
        true,
        true,
    )
    .await?;
    assert_eq!(echoed, Some(session_id), "the edge echoes the id the home parks under");
    assert!(ack_prefix_confirmed, "the edge owes this client the home's upstream offset");

    let mut framed = Vec::new();
    encode_frame_into(&mut framed, &ss_handshake_frame(&edge_user, echo_addr, VIA_EDGE)?, &[])
        .expect("padding frame within u16 bounds");
    socket.send(WsMessage::Binary(framed.into())).await?;

    let want = FRAME_LEN_V1 + VIA_EDGE.len();
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        read_padded_ss_plaintext(&mut socket, &edge_user, want),
    )
    .await
    .context(
        "timed out decoding the padded downlink: an unpadded control frame desynchronises \
                 the padding decoder, so nothing downstream of it ever parses",
    )??;
    match parse_v1(&stream[..FRAME_LEN_V1]) {
        ParseResult::Valid { up_acked } => assert_eq!(
            up_acked,
            VIA_HOME.len() as u64,
            "the offset belongs to the session the home parked",
        ),
        other => {
            bail!("expected an ack-prefix v1 frame at the head of the padded stream, got {other:?}")
        },
    }
    assert_eq!(
        &stream[FRAME_LEN_V1..want],
        VIA_EDGE,
        "the payload must round-trip through the parked upstream behind the control frame",
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the resume must reuse the parked upstream, not dial a fresh one",
    );

    socket.close(None).await?;
    Ok(())
}

/// **The proof of the goal.** A session established on one node and resumed
/// through a node with a *different path and different credentials* keeps one
/// upstream, and the move is proven to have gone through the mesh.
///
/// This is the exact topology that was broken in production: every node serves
/// SS on its own path, under its own per-user secret, and only the user *label*
/// is shared cluster-wide. It works under v5 because the node the client lands
/// on terminates the client's crypto and the mesh carries plaintext — the home
/// never sees the edge's key, and the only identity that crosses the mesh is the
/// user name the edge attests, which is what the home checks its park's owner
/// against.
///
/// [`cluster_session_survives_edge_switch`] already pins the *switch* for the
/// byte-stream shape, but on a symmetric cluster — one path, one secret — so it
/// cannot distinguish "the relay works" from "both nodes happen to be
/// interchangeable". The asymmetry is asserted here rather than assumed:
/// neither node's key would open the other's client stream.
///
/// Three independent discriminators say this really crossed the mesh, because a
/// local fallback also echoes faithfully: the echo target's accept counter stays
/// at one (a fresh session would dial a second upstream), the edge echoes the
/// id the *home* parks under rather than a freshly minted one, and the home's
/// own mesh byte counters moved. That last one is deliberate:
/// `mesh_bytes_total{direction="down"}` reading zero fleet-wide was the symptom
/// a never-working relay hid behind for months, and nothing else in this suite
/// asserts it ever moves.
#[tokio::test]
async fn cluster_session_survives_a_move_between_nodes_with_different_paths_and_credentials()
-> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-asymmetric-psk";
    const VIA_HOME: &[u8] = b"chunk-one:";
    const VIA_EDGE: &[u8] = b"chunk-two";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    let (home, home_user) = spawn_asymmetric_ss_node(
        PSK,
        1,
        HashMap::new(),
        Duration::from_secs(4),
        HOME_SS_PATH,
        HOME_SS_SECRET,
        0,
    )
    .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, edge_user) = spawn_asymmetric_ss_node(
        PSK,
        2,
        peers,
        Duration::from_secs(4),
        EDGE_SS_PATH,
        EDGE_SS_SECRET,
        0,
    )
    .await?;

    // The asymmetry is the whole point, so it is proven, not assumed: same
    // person, genuinely different secrets on the two nodes.
    assert_eq!(home_user.id(), edge_user.id(), "the user label is shared cluster-wide");
    assert!(
        !home_user.matches_password(EDGE_SS_SECRET)?,
        "the home must not hold the edge's credential",
    );
    assert!(
        !edge_user.matches_password(HOME_SS_SECRET)?,
        "the edge must not hold the home's credential",
    );

    // 1. The client establishes on the home, on the home's path, under the
    //    home's credentials, and the home parks the upstream when it drops.
    let session_id =
        park_session_on_home_path(&home, HOME_SS_PATH, &home_user, echo_addr, VIA_HOME).await?;
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the first session must open exactly one upstream",
    );

    // 2. The client reconnects to the *edge*, on the edge's path, under the
    //    edge's credentials. Under the old design this was a black hole.
    let (mut socket, echoed) =
        connect_ws_h1(edge.listen_addr, EDGE_SS_PATH, Some(session_id), true).await?;
    assert_eq!(
        echoed,
        Some(session_id),
        "continuity: the edge must echo the id the client already holds",
    );

    // 3. The same upstream keeps serving, through the edge — and the reply comes
    //    back sealed under the *edge's* key, which the home does not have.
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&edge_user, echo_addr, VIA_EDGE)?))
        .await?;
    let plaintext = read_ss_plaintext(&mut socket, &edge_user, VIA_EDGE.len()).await?;
    assert_eq!(
        plaintext.as_slice(),
        VIA_EDGE,
        "the parked upstream must keep streaming across the node move",
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the move must reuse the parked upstream: the target sees a single source",
    );

    socket.close(None).await?;
    drop(socket);
    // The outcome is recorded when the splice ends and the home re-parks, so
    // wait for the park rather than scraping into a race.
    wait_for_park(&home, session_id).await?;

    let rendered = home.metrics.render_prometheus();
    assert!(
        mesh_bytes(&rendered, "up") >= VIA_EDGE.len() as u64,
        "the home must have taken the client's uplink off the mesh:\n{rendered}",
    );
    assert!(
        mesh_bytes(&rendered, "down") >= VIA_EDGE.len() as u64,
        "the home must have pushed the reply onto the mesh — a zero here is the \
         production symptom of a relay that never worked:\n{rendered}",
    );
    assert_eq!(
        mesh_relay_outcome(&rendered, "hit"),
        1,
        "the home must have served exactly one relayed session:\n{rendered}",
    );
    assert_eq!(
        mesh_relay_rejected(&rendered, "no_session"),
        0,
        "the home held the park, so nothing may have been refused:\n{rendered}",
    );
    Ok(())
}

/// Downlink replay across the move has no gap and no duplicate: the resumed
/// carrier continues at exactly the offset the client acknowledged.
///
/// This is the half of continuity a payload echo cannot see. The home keeps a v2
/// ring of the plaintext it committed to send; when the session moves, the edge
/// forwards the client's raw v2 advertisement and acked offset in the mesh OPEN,
/// and the home writes the unacked suffix — and only that suffix — ahead of any
/// fresh byte. Replaying from `0` would duplicate what the client already has;
/// skipping the replay would leave a hole. Neither is distinguishable from a
/// working session by any other assertion in this suite.
///
/// The edge must **withhold** the v2 confirmation while doing so: the suffix
/// arrives as undelimited plaintext at the head of the mesh body, so the edge
/// cannot wrap it in the framed `"ORDR"` reply a v2 client expects. Both nodes
/// have v2 enabled in their own config, which is what gives that assertion
/// teeth — the request-derived echo the edge *would* produce confirms v2, so
/// only a genuinely relayed echo can withhold it.
///
/// The resuming carrier sends a target header with an **empty** payload on
/// purpose: nothing new reaches the target, so everything the client reads is
/// what the move owed it, and "no duplicate" can be asserted as an exact length.
#[tokio::test]
async fn cluster_relayed_downlink_replay_has_no_gap_and_no_duplicate() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-replay-psk";
    const SENT: &[u8] = b"HELLO-WORLD!";
    /// What the client claims it observed before the carrier died — `SENT`
    /// split so the suffix is neither empty nor the whole thing.
    const ACKED: u64 = 5;
    const UNACKED: &[u8] = b"-WORLD!";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    let (home, home_user) = spawn_asymmetric_ss_node(
        PSK,
        1,
        HashMap::new(),
        Duration::from_secs(4),
        HOME_SS_PATH,
        HOME_SS_SECRET,
        V2_DOWNLINK_BUFFER_BYTES,
    )
    .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, edge_user) = spawn_asymmetric_ss_node(
        PSK,
        2,
        peers,
        Duration::from_secs(4),
        EDGE_SS_PATH,
        EDGE_SS_SECRET,
        V2_DOWNLINK_BUFFER_BYTES,
    )
    .await?;

    // Session #0 on the home, negotiated as v1+v2 so a downlink ring exists at
    // all, and driven far enough that the ring holds something to replay.
    let (mut socket, first) =
        connect_ws_h1_symmetric_replay(home.listen_addr, HOME_SS_PATH, None, 0).await?;
    let session_id = first
        .issued_session_id
        .context("the home must mint a resume id for a resume-capable client")?;
    assert!(
        first.ack_prefix_confirmed && first.symmetric_replay_confirmed,
        "without a v2 negotiation on the original session there is no ring to replay from: \
         {first:?}",
    );
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&home_user, echo_addr, SENT)?))
        .await?;
    let echoed = read_ss_plaintext(&mut socket, &home_user, SENT.len()).await?;
    assert_eq!(echoed.as_slice(), SENT, "the home's own session must reach the target");
    socket.close(None).await?;
    drop(socket);
    wait_for_park(&home, session_id).await?;

    // The move: a different node, a different path, a different credential — and
    // a client that admits to having observed only the first `ACKED` bytes.
    let (mut socket, resumed) =
        connect_ws_h1_symmetric_replay(edge.listen_addr, EDGE_SS_PATH, Some(session_id), ACKED)
            .await?;
    assert_eq!(
        resumed.issued_session_id,
        Some(session_id),
        "the replay is only meaningful if this really continued the parked session: {resumed:?}",
    );
    assert!(
        resumed.ack_prefix_confirmed,
        "the edge re-emits the home's upstream offset, so it owes the client v1: {resumed:?}",
    );
    assert!(
        !resumed.symmetric_replay_confirmed,
        "a relayed echo must withhold v2 — a client told v2 is active would read the undelimited \
         replay suffix as an ORDR frame header and die: {resumed:?}",
    );

    // An empty payload: the target is given nothing new to echo, so the whole
    // downlink is what the move owed the client.
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&edge_user, echo_addr, b"")?))
        .await?;

    let want = FRAME_LEN_V1 + UNACKED.len();
    let stream = read_ss_plaintext(&mut socket, &edge_user, want).await?;
    match parse_v1(&stream[..FRAME_LEN_V1]) {
        ParseResult::Valid { up_acked } => assert_eq!(
            up_acked,
            SENT.len() as u64,
            "the edge must pass on the home's real upstream offset, not a fresh zero",
        ),
        other => bail!("expected an ack-prefix v1 frame at the head of the stream, got {other:?}"),
    }
    assert_eq!(
        &stream[FRAME_LEN_V1..],
        UNACKED,
        "replay must resume precisely at the acked offset: no gap, no duplicate",
    );
    assert_eq!(
        stream.len(),
        want,
        "nothing beyond the unacked suffix may follow: a replay from zero would show up here",
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the move must have reused the parked upstream, not dialled a fresh one",
    );
    socket.close(None).await?;
    Ok(())
}

/// A refusal leaves the client **genuinely served locally**, not silently
/// stalled — and the home says why on a counter an operator can alert on.
///
/// The black-hole invariant, for the byte-stream shape. The home here is healthy
/// and reachable; it simply holds no park under the id, which is the ordinary
/// answer for every expired session and every id it never minted. Because the
/// edge waits for that answer before upgrading the client's carrier, it still
/// has the choice to serve the client itself, and both halves of that are
/// asserted: the id it echoes is its **own** (echoing the refused one back would
/// send the client's next reconnect to the same home, to be refused and served
/// locally again — a session that can never resume), and the payload actually
/// round-trips through an upstream this node dialled.
///
/// [`cluster_udp_relay_falls_back_locally_when_the_home_holds_no_park`] pins the
/// same fallback for SS-UDP, and
/// [`cluster_unreachable_home_falls_back_to_local_session`] pins the *unreachable*
/// home for the byte stream. Neither covers this one: a reachable home that
/// refuses is a different code path on both ends — the home's `no_session`
/// refusal runs at all, and the edge degrades after an ack it did receive — and
/// nothing else in this suite asserts the refusal reason for a byte stream.
#[tokio::test]
async fn cluster_relay_refusal_leaves_the_client_served_locally() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-refusal-psk";
    const SERVED: &[u8] = b"served locally";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    // A healthy, reachable home that simply holds no park: nothing was ever
    // established against it.
    let (home, _home_user) = spawn_asymmetric_ss_node(
        PSK,
        1,
        HashMap::new(),
        Duration::from_secs(4),
        HOME_SS_PATH,
        HOME_SS_SECRET,
        0,
    )
    .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, edge_user) = spawn_asymmetric_ss_node(
        PSK,
        2,
        peers,
        Duration::from_secs(4),
        EDGE_SS_PATH,
        EDGE_SS_SECRET,
        0,
    )
    .await?;

    // A resume id whose shard points at the home, with no park behind it.
    let stale = resume_id_for_shard(PSK, 1)?;
    let (mut socket, issued) =
        connect_ws_h1(edge.listen_addr, EDGE_SS_PATH, Some(stale), true).await?;
    let issued = issued.context("the edge must issue a session id of its own")?;
    assert_ne!(
        issued, stale,
        "a fresh session mints a new id: echoing the refused one back can never resume",
    );

    socket
        .send(WsMessage::Binary(ss_handshake_frame(&edge_user, echo_addr, SERVED)?))
        .await?;
    let plaintext = read_ss_plaintext(&mut socket, &edge_user, SERVED.len()).await?;
    assert_eq!(
        plaintext.as_slice(),
        SERVED,
        "the client must be genuinely served, not silently stalled",
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the edge must have dialled an upstream of its own",
    );

    // The operator-visible half. The refusal is the home's, and each node has its
    // own recorder, so this scrape names only what the home counted. It is
    // already settled: the edge cannot have upgraded its client before the
    // refusal that produced these series reached it.
    let rendered = home.metrics.render_prometheus();
    assert_eq!(
        mesh_relay_rejected(&rendered, "no_session"),
        1,
        "a home with no park must count the refusal under its own reason:\n{rendered}",
    );
    assert_eq!(
        mesh_relay_outcome(&rendered, "miss"),
        1,
        "and record the outcome as a miss, so the series reconciles:\n{rendered}",
    );
    assert_eq!(mesh_relay_outcome(&rendered, "hit"), 0, "nothing was spliced:\n{rendered}",);
    assert_eq!(
        mesh_bytes(&rendered, "down"),
        0,
        "a refused relay must push nothing onto the mesh:\n{rendered}",
    );

    socket.close(None).await?;
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

/// When the edge has no mesh route to the resume id's home shard, opening the
/// relay fails and the edge must degrade to a fresh local session rather than
/// drop the client. The echo target sees a fresh upstream connect.
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

/// The two tests above answer only for *session-creating* requests. An XHTTP
/// session outlives the request that created it, and every later request on the
/// same id answers with its own response echo — so the withholding has to hold
/// there too, and that is the half the pins were missing.
///
/// An attaching request has no relay to ask: `xhttp_edge` short-circuits on an id
/// that is already live, precisely so a second request does not open (and waste)
/// a mesh stream. Deriving the echo from *that* request's headers instead is
/// therefore the same v2 lie the create path was fixed for, re-entered through
/// the attach path — and it is reachable end to end, because an `xhttp_h2` /
/// `xhttp_h3` `stream-one` dial that fails *after* the server created the
/// session falls back to a plain GET on the same `XhttpTarget`, hence the same
/// session id.
///
/// Both attach shapes an axum XHTTP session really sees are pinned: a packet-up
/// POST landing on a session a GET created, and a GET landing on a session a
/// POST created. The session id in [`assert_relayed_edge_echo`] is what keeps
/// each honest — it is the relayed id, which only a request reading back the
/// creating request's decision can echo.
#[tokio::test]
async fn cluster_xhttp_attach_echo_withholds_symmetric_replay() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-xhttp-attach-echo-psk";
    let (echo_addr, _accepts) = spawn_echo_target().await?;

    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), Some("/ssx"), None)
            .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_xhttp_v2_node(PSK, 2, peers, Duration::from_secs(4), "/ssx").await?;
    let client = http_client();

    // 1. A GET creates the relayed session; a POST at seq = 0 then attaches to
    // it. The GET response body is held open for the whole case so the session
    // cannot be swept out from under the POST.
    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let uri = format!("http://{}/ssx/attach-echo-get-first", edge.listen_addr);
    let request = with_v2_resume_headers(Request::builder().method(Method::GET).uri(&uri), parked)
        .body(Full::new(Bytes::new()))?;
    let created = client.request(request).await?;
    assert_eq!(created.status(), StatusCode::OK, "the creating GET must be served");
    assert_relayed_edge_echo(created.headers(), parked, "creating packet-up GET")?;

    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .header("x-xhttp-seq", "0"),
        parked,
    )
    .body(Full::new(Bytes::new()))?;
    let attached = client.request(request).await?;
    assert_eq!(attached.status(), StatusCode::OK, "the attaching POST must be served");
    assert_relayed_edge_echo(attached.headers(), parked, "attaching packet-up POST")?;
    drop(created);

    // 2. The other order: a POST at seq = 0 creates, a GET attaches.
    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let uri = format!("http://{}/ssx/attach-echo-post-first", edge.listen_addr);
    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .header("x-xhttp-seq", "0"),
        parked,
    )
    .body(Full::new(Bytes::new()))?;
    let created = client.request(request).await?;
    assert_eq!(created.status(), StatusCode::OK, "the creating POST must be served");
    assert_relayed_edge_echo(created.headers(), parked, "creating packet-up POST")?;

    let request = with_v2_resume_headers(Request::builder().method(Method::GET).uri(&uri), parked)
        .body(Full::new(Bytes::new()))?;
    let attached = client.request(request).await?;
    assert_eq!(attached.status(), StatusCode::OK, "the attaching GET must be served");
    assert_relayed_edge_echo(attached.headers(), parked, "attaching packet-up GET")?;
    drop(attached);

    Ok(())
}

/// The xhttp/h3 twin of [`cluster_xhttp_attach_echo_withholds_symmetric_replay`].
/// h3 carries its own copy of the response-echo code, so the attach path needs
/// its own pin there too: a packet-up POST at `seq = 0` creates the relayed
/// session and a packet-up GET attaches to it.
#[tokio::test]
async fn cluster_xhttp_h3_attach_echo_withholds_symmetric_replay() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-xhttp-h3-attach-echo-psk";
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
    let uri = format!("https://localhost:{}/ssx/attach-echo-h3", edge.addr.port());

    let parked = park_session_on_home(&home, &user, echo_addr, b"").await?;
    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .version(Version::HTTP_3)
            .header("x-xhttp-seq", "0"),
        parked,
    )
    .body(())?;
    let mut req_stream = send_request.send_request(request).await?;
    req_stream.finish().await?;
    let response = req_stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK, "the creating xhttp/h3 POST must be served");
    assert_relayed_edge_echo(response.headers(), parked, "creating xhttp/h3 POST")?;
    drop(req_stream);

    let request = with_v2_resume_headers(
        Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .version(Version::HTTP_3),
        parked,
    )
    .body(())?;
    let mut req_stream = send_request.send_request(request).await?;
    req_stream.finish().await?;
    let response = req_stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK, "the attaching xhttp/h3 GET must be served");
    assert_relayed_edge_echo(response.headers(), parked, "attaching xhttp/h3 GET")?;
    drop(req_stream);

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

/// A closing SS-UDP-over-XHTTP client must park its session *now*, the way the
/// WS carrier does — not sit live until the 180 s idle sweep.
///
/// The park is what a cross-transport resume takes over, so a carrier that only
/// releases it on idle eviction cannot be soft-switched: the redial finds no
/// park, opens a fresh upstream, and the flow's NAT entries stay pinned to a
/// carrier nobody is reading. XHTTP packet-up has no transport-level FIN — every
/// request is its own — so the close has to travel as the `X-Xhttp-Fin` hint on
/// the session's final POST.
///
/// Split `/ssu` (no combined discriminator) keeps this on the plainest SS-UDP
/// shape: the failure is in the carrier, not in path resolution.
#[tokio::test]
async fn xhttp_udp_client_close_parks_session() -> Result<()> {
    const PSK: &[u8] = b"xhttp-udp-close-park-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    let (node, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, Some("/ssu"))
            .await?;

    let url = Url::parse(&format!("http://{}/ssu", node.listen_addr))?;
    // Round-trips a datagram, closes the transport, then waits for the park —
    // the same helper the WS carriers already satisfy in milliseconds.
    park_udp_client_session_on_home(
        &node,
        &url,
        TransportMode::XhttpH2,
        CipherKind::Chacha20IetfPoly1305,
        "secret-b",
        None,
        "xhttp-udp-close-park",
        target_addr,
    )
    .await?;
    Ok(())
}

/// The teardown the TUN data plane actually performs: the transport is
/// **dropped**, never closed. `close_udp_flow` drops the flow state and lets the
/// `AbortOnDrop` chain release the carrier — no `transport.close()` anywhere on
/// that path — so a park that only happens on an explicit close would never
/// happen for a tunnelled flow, which is the one that soft-switches.
///
/// Dropping aborts the client's XHTTP driver task, so the FIN has to survive the
/// abort: it is issued from the driver's own drop guard, detached.
#[tokio::test]
async fn xhttp_udp_client_drop_parks_session() -> Result<()> {
    const PSK: &[u8] = b"xhttp-udp-drop-park-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    let (node, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, Some("/ssu"))
            .await?;

    let url = Url::parse(&format!("http://{}/ssu", node.listen_addr))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let (transport, issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH2,
        CipherKind::Chacha20IetfPoly1305,
        "secret-b",
        None,
        false,
        "xhttp-udp-drop-park",
        None,
        None,
        None,
    )
    .await?;
    let issued = issued.context("a resume-capable dial must be issued a session id")?;

    transport.send_packet(&ss_first_chunk(target_addr, b"seed")).await?;
    let reply = transport.read_packet().await?;
    anyhow::ensure!(reply.ends_with(b"seed"), "the node must serve the seeding datagram itself");

    drop(transport);
    wait_for_park(&node, SessionId::from_bytes(*issued.as_bytes())).await?;
    Ok(())
}

/// The h3 twin of [`xhttp_udp_client_close_parks_session`], on the combined
/// `/ssc` base the owner actually deploys. XHTTP-over-h3 has its own request
/// handler on the server *and* its own packet-up driver on the client, so
/// neither end's half of the FIN is covered by the h2 case.
#[tokio::test]
async fn xhttp_h3_udp_client_close_parks_session() -> Result<()> {
    const PSK: &[u8] = b"xhttp-h3-udp-close-park-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;
    let (node, _user) =
        spawn_combined_xhttp_h3_node(PSK, 1, HashMap::new(), Duration::from_secs(4), "/ssc")
            .await?;

    // h3 mandates `https://`; the shared test root is installed on the client by
    // the node spawner, so the dial trusts the self-signed cert.
    let url = Url::parse(&format!("https://localhost:{}/ssc", node.addr.port()))?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));
    let (transport, issued, _downgraded) = UdpWsTransport::connect_with_resume(
        &cache,
        &url,
        TransportMode::XhttpH3,
        CipherKind::Chacha20IetfPoly1305,
        "secret-b",
        None,
        false,
        "xhttp-h3-udp-close-park",
        None,
        None,
        // Combined base → the hidden UDP discriminator rides the session id.
        Some(SsPathKind::Udp),
    )
    .await?;
    let issued = issued.context("a resume-capable dial must be issued a session id")?;

    transport.send_packet(&ss_first_chunk(target_addr, b"seed")).await?;
    let reply = transport.read_packet().await?;
    anyhow::ensure!(reply.ends_with(b"seed"), "the node must serve the seeding datagram itself");

    transport.close().await?;
    wait_for_park_in(&node.registry, SessionId::from_bytes(*issued.as_bytes())).await?;
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
    let (home, user) = spawn_cluster_node(
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

    // Establish against the home first: a v5 relay resumes a park, it never
    // creates a session. Seeded over the home's WS `/udp` leg — a park is a set
    // of NAT keys and an owner, with no carrier or path attached to it.
    let session_id = park_udp_session_on_home(&home, "/udp", &user, target_addr, b"seed").await?;
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

    // Establish against the home first: a v5 relay resumes a park, it never
    // creates a session.
    let home_url = Url::parse(&format!("ws://{}/ssc", home.listen_addr))?;
    let client_resume = park_udp_client_session_on_home(
        &home,
        &home_url,
        TransportMode::WsH1,
        CipherKind::Chacha20IetfPoly1305,
        "secret-b",
        Some(SsPathKind::Udp),
        "cluster-udp-combined-ws-seed",
        target_addr,
    )
    .await?;

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

/// The padded **SS-TCP** carrier path, for the same reason and with the same
/// discipline as [`COMBINED_PADDED_PATH`]: padded here, so the byte-stream
/// carriers every other test dials on `/tcp` stay on the plain wire.
const SS_TCP_PADDED_PATH: &str = "/tcp-pad";

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
        paths: vec![COMBINED_PADDED_PATH.to_string(), SS_TCP_PADDED_PATH.to_string()],
        throttle_detect_enabled: false,
        throttle_ratio_percent: 200,
        throttle_window_secs: 1,
        throttle_sustain_windows: 1,
        throttle_min_bytes_per_sec: 0,
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
/// one atomic AEAD datagram; the edge decrypts it and length-frames the
/// plaintext onto the mesh stream, and the home de-frames it, forwards to the
/// target and relays the echo back. Distinct sizes (incl. a 1200-byte packet)
/// exercise the datagram framing that is the SS-UDP relay's main
/// silent-corruption risk — a byte splice would coalesce or split packets and
/// break per-packet delivery.
#[tokio::test]
async fn cluster_udp_relays_datagrams_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-relay-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Home owns shard 1; an edge (shard 2) relays /udp to it over the mesh.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // The park comes first: a v5 relay carries only a session the home already
    // holds, so a fabricated id would be refused and served locally — which
    // would still echo, and would prove nothing about the relay.
    let session_id = park_udp_session_on_home(&home, "/udp", &user, target_addr, b"seed").await?;
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

/// An SS-UDP session survives an edge switch: established against its home, then
/// resumed through one edge and through a *different* edge, both relaying to that
/// home over the mesh. The home re-points the parked NAT entry at each new relay
/// stream instead of binding a fresh upstream socket, so the target sees exactly
/// one source address across all three carriers. The mesh counterpart of
/// `ss_udp_resume_hit_reattaches_parked_nat_entry`.
///
/// The first connect goes to the home directly because that is the only thing
/// that mints a park: with client crypto on the edge, the mesh carries only
/// sessions the home already owns. The second edge additionally proves the home
/// **re-parks** the NAT keys after a relayed splice ends — a session that
/// survived one switch and not the next would still pass a two-carrier test.
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

    // Session #0, direct against the home: binds the one upstream socket the
    // whole test then follows, and parks its key on close.
    let session_id = park_udp_session_on_home(&home, "/udp", &user, target_addr, b"udp-0").await?;
    assert_eq!(sources.lock().await.len(), 1, "the home must open exactly one upstream source");

    // Session #1 via edge A: the home's park hits → the entry is re-pointed at
    // the relay, and the responses are sealed by the edge.
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
        "the first relay must reuse the parked NAT entry, not bind a second socket"
    );
    sock_a.close(None).await?;
    drop(sock_a);
    // The home re-parks the NAT keys once the mesh stream ends.
    wait_for_park(&home, session_id).await?;

    // Session #2 via edge B, same id: proves the re-park above is usable.
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
///
/// Both sessions are established against the home first: a v5 relay only ever
/// resumes a park the home already holds, so without that step each carrier
/// would be served locally by its own edge and the two would never meet on one
/// NAT table.
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

    // Two DISTINCT sessions (not a resume of one another), each established
    // against the home so each has a park for its edge to relay onto.
    let session_a = park_udp_session_on_home(&home, "/udp", &user, target_addr, b"seed-a").await?;
    let session_b = park_udp_session_on_home(&home, "/udp", &user, target_addr, b"seed-b").await?;
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

/// A relayed SS-UDP carrier whose home holds no park under the presented id must
/// degrade to a fresh local session on the edge, not disappear.
///
/// This is the ordinary outcome now that the edge terminates the client's
/// crypto: the home is asked only "is there a park under this id?", and answers
/// no for every id it never minted, for every park that has expired, and for a
/// home whose cluster config diverged. Because the edge waits for that answer
/// before upgrading the client carrier, it still has the choice to serve the
/// client itself — which is what this asserts, on both halves of the fallback:
/// the datagram round-trips through the edge's own session, **and** the echoed
/// session id is the edge's own. Echoing the presented id back would send the
/// client's next reconnect straight to the home that just refused it, be refused
/// again, and be served locally again: a session that can never resume.
///
/// This replaced the v4 `CloseReason::NoRoute` refusal — an asymmetric-config
/// home resolving the edge's request path to an empty route table — which went
/// with the route lookup itself when v4 was retired: a home resolves no path at
/// all now, so "no park under this id" is the only setup refusal left.
#[tokio::test]
async fn cluster_udp_relay_falls_back_locally_when_the_home_holds_no_park() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-nopark-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // A healthy, reachable home that simply holds no park: nothing was ever
    // established against it.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // A plausible-looking home-shard id the home has never seen.
    let session_id = resume_id_for_shard(PSK, 1)?;
    let (mut socket, issued) =
        connect_ws_h1(edge.listen_addr, "/udp", Some(session_id), true).await?;
    let issued = issued.context("the edge must issue a session id of its own")?;
    assert_ne!(
        issued, session_id,
        "a refused relay must echo the id this edge will park under, not the foreign one",
    );

    let mut plaintext = TargetAddr::from(target_addr).to_wire_bytes()?;
    plaintext.extend_from_slice(b"not-into-the-void");
    socket
        .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
        .await?;

    // The home refused the relay, so the edge served this carrier locally: the
    // datagram reaches the target and the echo comes back.
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

/// A session established on a **direct** carrier and resumed through a **relay**
/// keeps its upstream socket, and its responses keep arriving — now sealed by
/// the edge instead of the home.
///
/// The home re-points the parked NAT entry at the relay under
/// [`crate::server::nat::UdpResponseCoding::Plaintext`] and stops sealing
/// anything: it holds no key. What comes back over the mesh is the same
/// SOCKS5-wrapped body it would have encrypted, and the edge seals it under the
/// client's own key. An SS-2022 cipher is deliberate — it is the only one whose
/// response carries a server session id and a packet counter, so a reply the
/// client can open proves the whole seal, not just that bytes moved.
#[tokio::test]
async fn cluster_udp_direct_park_resumes_through_a_relay() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-direct-to-relay-psk";
    let (target_addr, sources) = spawn_echo_udp_target().await?;

    let (home, _user) = spawn_ss2022_node(PSK, 1, HashMap::new(), Duration::from_secs(4)).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_ss2022_node(PSK, 2, peers, Duration::from_secs(4)).await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));

    // Leg 1, direct against the home: the NAT entry is created under
    // `UdpResponseCoding::Ss`, so the home seals its own responses.
    let home_url = Url::parse(&format!("ws://{}/udp", home.listen_addr))?;
    let (direct, issued, _downgraded) = ss2022_udp_client(&cache, &home_url, None).await?;
    let echo = ss2022_roundtrip(&direct, target_addr, b"direct").await?;
    assert!(echo.ends_with(b"direct"), "the home must serve the direct leg: {echo:?}");
    let issued = issued.context("a resume-capable dial must be issued a session id")?;
    direct.close().await?;
    wait_for_park(&home, SessionId::from_bytes(*issued.as_bytes())).await?;
    let bound = sources.lock().await.clone();
    assert_eq!(bound.len(), 1, "the direct leg must bind exactly one upstream socket");

    // Leg 2, through the edge: the home hands the same socket to a relayed
    // carrier and answers in plaintext; the edge seals for the client.
    let edge_url = Url::parse(&format!("ws://{}/udp", edge.listen_addr))?;
    let (relayed, _issued, _downgraded) =
        ss2022_udp_client(&cache, &edge_url, Some(issued)).await?;
    let echo = ss2022_roundtrip(&relayed, target_addr, b"relayed").await?;
    assert!(
        echo.ends_with(b"relayed"),
        "the edge must seal the home's plaintext response under the client's key: {echo:?}",
    );
    assert_eq!(
        sources.lock().await.clone(),
        bound,
        "the relayed carrier must reuse the parked upstream socket, not bind a new one",
    );

    relayed.close().await?;
    Ok(())
}

/// The mirror direction: a NAT entry **created by a relayed carrier** is later
/// served by a **direct** one, and its SS-2022 responses still seal.
///
/// A relayed carrier attaches with no key at all, so it cannot read a server
/// session id off the datagram that creates an entry the way a decrypting
/// carrier does. `ServerSessionId::for_coding` therefore reserves one anyway for
/// `UdpResponseCoding::Plaintext` — eight random bytes the relayed path never
/// reads, and exactly what a later direct carrier needs to seal responses out of
/// that same socket. With `Omit` instead, leg 3 below fails every response with
/// `CryptoError::InvalidHeader` and the read times out.
///
/// Target B is introduced *on the relayed leg* on purpose: that is the only way
/// to make the home create an entry under the plaintext coding.
#[tokio::test]
async fn cluster_udp_relayed_nat_entry_resumes_on_a_direct_carrier() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-relay-to-direct-psk";
    let (target_a, _sources_a) = spawn_echo_udp_target().await?;
    let (target_b, sources_b) = spawn_echo_udp_target().await?;

    let (home, _user) = spawn_ss2022_node(PSK, 1, HashMap::new(), Duration::from_secs(4)).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_ss2022_node(PSK, 2, peers, Duration::from_secs(4)).await?;
    let cache = ClientDnsCache::new(Duration::from_secs(30));

    // Leg 1, direct: establishes the session and parks it. Target A only.
    let home_url = Url::parse(&format!("ws://{}/udp", home.listen_addr))?;
    let (direct, issued, _downgraded) = ss2022_udp_client(&cache, &home_url, None).await?;
    let echo = ss2022_roundtrip(&direct, target_a, b"seed").await?;
    assert!(echo.ends_with(b"seed"), "the home must serve the seeding leg: {echo:?}");
    let issued = issued.context("a resume-capable dial must be issued a session id")?;
    direct.close().await?;
    wait_for_park(&home, SessionId::from_bytes(*issued.as_bytes())).await?;

    // Leg 2, relayed: the first datagram for target B creates its NAT entry
    // while the carrier is a *relayed* one, i.e. under the plaintext coding.
    let edge_url = Url::parse(&format!("ws://{}/udp", edge.listen_addr))?;
    let (relayed, _issued, _downgraded) =
        ss2022_udp_client(&cache, &edge_url, Some(issued)).await?;
    let echo = ss2022_roundtrip(&relayed, target_b, b"via-relay").await?;
    assert!(echo.ends_with(b"via-relay"), "the relayed leg must reach target B: {echo:?}");
    let bound_b = sources_b.lock().await.clone();
    assert_eq!(bound_b.len(), 1, "target B must see exactly one upstream socket");
    relayed.close().await?;
    wait_for_park(&home, SessionId::from_bytes(*issued.as_bytes())).await?;

    // Leg 3, direct again: the home takes the plaintext-created entry back and
    // seals target B's responses itself.
    let (back, _issued, _downgraded) = ss2022_udp_client(&cache, &home_url, Some(issued)).await?;
    let echo = ss2022_roundtrip(&back, target_b, b"back-direct").await?;
    assert!(
        echo.ends_with(b"back-direct"),
        "a direct carrier must be able to seal responses out of a socket a relayed carrier \
         created — that is what the reserved server session id is for: {echo:?}",
    );
    assert_eq!(
        sources_b.lock().await.clone(),
        bound_b,
        "the hand-back must reuse the socket the relayed carrier created",
    );

    back.close().await?;
    Ok(())
}

/// A real SS-UDP client on an **SS-2022** cipher, dialling `url` over plain WS.
/// SS-2022 is what puts a server session id and a packet counter on every
/// response, which is the only way a test can tell whether the id a NAT entry
/// reserved is the one being used.
async fn ss2022_udp_client(
    cache: &ClientDnsCache,
    url: &Url,
    resume: Option<ClientSessionId>,
) -> Result<(UdpWsTransport, Option<ClientSessionId>, Option<TransportMode>)> {
    UdpWsTransport::connect_with_resume(
        cache,
        url,
        TransportMode::WsH1,
        CipherKind::Aes128Gcm2022,
        SS2022_PSK,
        None,
        false,
        "cluster-udp-handover-test",
        None,
        resume,
        None,
    )
    .await
}

/// Sends one datagram and returns the echo, bounded so a seal that silently
/// fails surfaces as a failed assertion rather than a hung test.
async fn ss2022_roundtrip(
    transport: &UdpWsTransport,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Bytes> {
    transport.send_packet(&ss_first_chunk(target, payload)).await?;
    tokio::time::timeout(Duration::from_secs(5), transport.read_packet())
        .await
        .context("no response came back — a response the client cannot open never arrives")?
}

/// SS-UDP over XHTTP relays through the mesh. The client drives the real
/// `UdpWsTransport` (packet-up h2) against the edge with a home-shard resume id;
/// the edge terminates the client's crypto and relays plaintext datagrams to the
/// home with `MeshFraming::Udp`, and the home routes them to the target from the
/// park's own NAT keys. Proves the XHTTP datagram edge path end to end,
/// byte-exact.
#[tokio::test]
async fn cluster_udp_xhttp_relays_to_home() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-udp-xhttp-psk";
    let (target_addr, _sources) = spawn_echo_udp_target().await?;

    // Home resolves `/ssu` on its `xhttp_ss_udp` table and runs the mesh
    // listener; the edge serves `/ssu` and relays a foreign-shard resume.
    let (home, user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, Some("/ssu"))
            .await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) =
        spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, Some("/ssu")).await?;

    // Establish against the home first: a v5 relay carries only a session the
    // home already holds, so a fabricated id would be refused and served locally.
    // The park is seeded over the home's WS `/udp` leg because a park is a set of
    // NAT keys and an owner — it carries no carrier and no path — which makes
    // this leg a cross-transport resume as well.
    let session_id = park_udp_session_on_home(&home, "/udp", &user, target_addr, b"seed").await?;
    let client_resume = ClientSessionId::from_bytes(*session_id.as_bytes());

    // Real client: SS-UDP over XHTTP (h2 packet-up) to the edge, resuming the
    // parked id so the edge relays the datagram carrier over the mesh.
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
/// mesh with `MeshFraming::Udp`, and the home forwards to the target. A
/// byte-exact echo proves the h3 SS-UDP accept branch end to end (the `H3Ws`
/// carrier, a different `WsSocket` impl than the h1/h2 path).
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

    // The park comes first: a v5 relay carries only a session the home holds.
    let session_id = park_udp_session_on_home(&home, "/udp", &user, target_addr, b"seed").await?;

    // h3 client → edge, CONNECT `/udp` presenting the parked resume id.
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

/// Reads `want` whole VLESS-UDP datagrams off the carrier, in order.
///
/// Unlike [`read_vless_udp_datagram`] this keeps its buffer across datagrams, so
/// the *boundaries* are what it asserts: each returned entry is one
/// length-prefixed frame as the client would de-frame it, whatever the WebSocket
/// framing did with them. A pair that coalesced upstream comes back as one
/// oversized entry rather than two, which is the failure this exists to catch.
async fn read_vless_udp_datagrams<S>(socket: &mut S, want: usize) -> Result<Vec<Vec<u8>>>
where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut out = Vec::with_capacity(want);
    loop {
        // Drop an optional leading VLESS response header once it is fully
        // present, exactly as the single-datagram helper does.
        if out.is_empty() && buf.len() >= 2 && buf[0] == VLESS_VERSION && buf[1] == 0x00 {
            buf.drain(..2);
        }
        while out.len() < want && buf.len() >= 2 {
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if buf.len() < 2 + len {
                break;
            }
            out.push(buf[2..2 + len].to_vec());
            buf.drain(..2 + len);
        }
        if out.len() == want {
            return Ok(out);
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

// ── Cross-protocol continuity across the mesh ─────────────────────────────────

/// A byte-stream park minted over Shadowsocks, resumed through an edge that
/// terminated **VLESS** — and payload crossing the home's splice in both
/// directions.
///
/// The home half of this is pinned by
/// `transport::tests::mesh_relay::v5_home_splices_an_ss_park_onto_a_vless_relay`
/// against a scripted edge. Nothing pinned the two halves *together*: a relay
/// whose home hands the park over and whose edge then carries no bytes reads, on
/// every counter the home publishes, exactly like a working one — `hit` is
/// recorded by the home the moment the splice ends, however it ended. So the
/// discriminator here is deliberately not the hand-off but the traffic:
/// `mesh_bytes_total{role="home"}` must move in **both** directions, and the
/// echo target must answer through the socket the home already had open.
///
/// This is the `shuffle_wires` case reduced to two nodes: one `[[users]]` entry
/// carrying both `password` and `vless_id`, two legs rerolling their active wire
/// independently, so about half the time the edge that resumes terminates a
/// different protocol than the one that parked.
#[tokio::test]
async fn cluster_ss_park_resumes_through_a_vless_edge() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-cross-ss-to-vless";
    /// Written by the home's own SS session, so its upstream socket has taken
    /// these bytes — and `upstream_bytes_acked` is non-zero — before it parks.
    const VIA_HOME: &[u8] = b"seventeen-bytes!!";
    const VIA_EDGE: &[u8] = b"after-the-reroll";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    let (home, ss_user) =
        spawn_dual_protocol_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4)).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_dual_protocol_cluster_node(PSK, 2, peers, Duration::from_secs(4)).await?;

    // Park over Shadowsocks: `ParkedProtocol::Ss`, owner "bob".
    let session_id = park_session_on_home(&home, &ss_user, echo_addr, VIA_HOME).await?;

    // Come back over VLESS with the same id and the same account.
    let (mut socket, echoed, ack_prefix_confirmed) =
        connect_ws_h1_ack_prefix(edge.listen_addr, "/vless", Some(session_id), true, true).await?;
    assert_eq!(
        echoed,
        Some(session_id),
        "a crossing is still a relayed resume: the edge echoes the id the home parks under",
    );
    assert!(
        ack_prefix_confirmed,
        "the edge re-emits the home's upstream offset, so it owes the client v1",
    );

    socket
        .send(WsMessage::Binary(vless_tcp_request(CLUSTER_VLESS_UUID, echo_addr, VIA_EDGE)?))
        .await?;

    // Read the VLESS byte stream in order: response header, control frame, echo.
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
            "the offset belongs to the session, not to the protocol that minted it",
        ),
        other => bail!("expected an ack-prefix v1 frame right after the header, got {other:?}"),
    }
    assert_eq!(
        &stream[2 + FRAME_LEN_V1..want],
        VIA_EDGE,
        "the payload must round-trip through the parked upstream after the crossing",
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the crossing must reuse the parked upstream, not dial a fresh one",
    );

    let rendered = home.metrics.render_prometheus();
    // The assertion a home-only view cannot make: bytes, not hand-offs.
    assert!(
        mesh_bytes(&rendered, "up") >= VIA_EDGE.len() as u64,
        "the uplink must carry the client's request across the splice: {rendered}",
    );
    assert!(
        mesh_bytes(&rendered, "down") >= VIA_EDGE.len() as u64,
        "the downlink must carry the target's answer back across the splice: {rendered}",
    );
    assert_eq!(
        cross_protocol_resumes(&rendered, "ss", "vless"),
        1,
        "the crossing is counted on the node that owns the park: {rendered}",
    );
    assert_eq!(
        mesh_relay_rejected(&rendered, "protocol_mismatch"),
        0,
        "a byte-stream park crosses freely: {rendered}",
    );

    socket.close(None).await?;
    Ok(())
}

/// The mirror of [`cluster_ss_park_resumes_through_a_vless_edge`]: a park minted
/// over **VLESS**, resumed through an edge that terminated Shadowsocks.
///
/// Worth its own case rather than a parameter, because the two directions run
/// different code on both ends. On the home the OPEN asks a different question
/// (`ParkQuery::Exact(Stream)` for an SS carrier against `AnyVless`), and on the
/// edge the client's framing is a continuous AEAD stream rather than a
/// length-prefixed VLESS one — so the control frame the client must find at the
/// head of it is produced by a different emitter.
#[tokio::test]
async fn cluster_vless_park_resumes_through_an_ss_edge() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-cross-vless-to-ss";
    const VIA_HOME: &[u8] = b"seventeen-bytes!!";
    const VIA_EDGE: &[u8] = b"after-the-reroll";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;

    let (home, _) =
        spawn_dual_protocol_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4)).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, edge_user) =
        spawn_dual_protocol_cluster_node(PSK, 2, peers, Duration::from_secs(4)).await?;

    // Park over VLESS: `ParkedProtocol::Vless`, owner "bob".
    let session_id = park_vless_session_on_home(&home, echo_addr, VIA_HOME).await?;

    let (mut socket, echoed, ack_prefix_confirmed) =
        connect_ws_h1_ack_prefix(edge.listen_addr, "/tcp", Some(session_id), true, true).await?;
    assert_eq!(
        echoed,
        Some(session_id),
        "a crossing is still a relayed resume: the edge echoes the id the home parks under",
    );
    assert!(ack_prefix_confirmed, "the edge owes this client the home's upstream offset");

    socket
        .send(WsMessage::Binary(ss_handshake_frame(&edge_user, echo_addr, VIA_EDGE)?))
        .await?;

    let want = FRAME_LEN_V1 + VIA_EDGE.len();
    let stream = read_ss_plaintext(&mut socket, &edge_user, want).await?;
    match parse_v1(&stream[..FRAME_LEN_V1]) {
        ParseResult::Valid { up_acked } => assert_eq!(
            up_acked,
            VIA_HOME.len() as u64,
            "the offset belongs to the session, not to the protocol that minted it",
        ),
        other => bail!("expected an ack-prefix v1 frame at the head of the stream, got {other:?}"),
    }
    assert_eq!(
        &stream[FRAME_LEN_V1..want],
        VIA_EDGE,
        "the payload must round-trip through the parked upstream after the crossing",
    );
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        1,
        "the crossing must reuse the parked upstream, not dial a fresh one",
    );

    let rendered = home.metrics.render_prometheus();
    assert!(
        mesh_bytes(&rendered, "up") >= VIA_EDGE.len() as u64,
        "the uplink must carry the client's request across the splice: {rendered}",
    );
    assert!(
        mesh_bytes(&rendered, "down") >= VIA_EDGE.len() as u64,
        "the downlink must carry the target's answer back across the splice: {rendered}",
    );
    assert_eq!(
        cross_protocol_resumes(&rendered, "vless", "ss"),
        1,
        "the crossing is counted on the node that owns the park: {rendered}",
    );
    assert_eq!(
        mesh_relay_rejected(&rendered, "protocol_mismatch"),
        0,
        "a byte-stream park crosses freely: {rendered}",
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

/// A VLESS-UDP session migrates across an edge switch: the same parked socket
/// serves a carrier that arrives on a different node, with a different path and
/// a different credential.
///
/// The guarantee this asserts — one upstream source across the switch — is the
/// one the v5 migration withdrew when the VLESS edge moved to plaintext relaying
/// and the home spliced only `Parked::Tcp`. It is back because the home now
/// names the shape of the park it holds in its setup ack, so an edge learns
/// *before* it reads the client's command that this id is a single-target
/// VLESS-UDP session, and the home has a splice for it.
///
/// Three properties ride on the single `sources` counter. The edge must relay
/// rather than bind its own socket (else a second source appears); the home must
/// re-park the socket when the mesh carrier ends (else the third connect binds
/// one); and the resume must survive the credential switch, because the edge
/// authenticates its client against its own UUID on its own path and the home
/// only ever sees the user *name* the edge attests.
#[tokio::test]
async fn cluster_vless_udp_survives_edge_switch() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-udp-switch-psk";
    let (target_addr, sources) = spawn_echo_udp_target().await?;

    // Home owns shard 1; the edge (shard 2) can relay to it, and serves VLESS on
    // its own path under its own UUID.
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_vless_cluster_node(
        PSK,
        2,
        peers,
        Duration::from_secs(4),
        "/vless-edge",
        EDGE_VLESS_UUID,
    )
    .await?;

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

    // Session #2 via the edge, same id, different path and credential. The home
    // acks the relay with the park's shape, the edge reads `VlessCommand::Udp`,
    // sees the shapes agree and relays the datagram home.
    //
    // Advertised as Ack-Prefix (v1) deliberately, because that flag is what puts
    // the home's `UpstreamAckFrame` on the mesh stream ahead of the first
    // datagram. Both ends of that frame are exercised only here: the home emits
    // it in `splice_plaintext_vless_udp` and the edge consumes it in
    // `attach_datagrams`. A disagreement would not error — it would shift the
    // first datagram's length prefix by eight bytes — so the byte-exact echo
    // below is the assertion that catches it. The client sees no v1 frame of its
    // own: VLESS-UDP has no uplink byte offset, exactly as on the direct path.
    let (mut sock_edge, echoed_id, ack_prefix_confirmed) =
        connect_ws_h1_ack_prefix(edge.listen_addr, "/vless-edge", Some(session_id), true, true)
            .await?;
    assert_eq!(
        echoed_id,
        Some(session_id),
        "a relayed session must echo the id the home parks under",
    );
    assert!(
        ack_prefix_confirmed,
        "the edge confirms v1 on the upgrade, before it can know the command",
    );
    sock_edge
        .send(WsMessage::Binary(vless_udp_request(
            EDGE_VLESS_UUID,
            target_addr,
            b"vless-edge",
        )?))
        .await?;
    let echoed = read_vless_udp_datagram(&mut sock_edge).await?;
    assert_eq!(
        echoed.as_slice(),
        b"vless-edge",
        "the relay must carry the VLESS-UDP datagram byte-exact",
    );
    assert_eq!(
        sources.lock().await.len(),
        1,
        "resume across the edge switch must reuse the parked UDP socket (one upstream source)",
    );
    sock_edge.close(None).await?;
    drop(sock_edge);

    // The home re-parks the socket once the mesh carrier ends, so the session
    // survives more than one switch.
    wait_for_park(&home, session_id).await?;
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
    assert_eq!(echoed.as_slice(), b"vless-back", "the re-parked socket still carries datagrams");
    assert_eq!(
        sources.lock().await.len(),
        1,
        "the re-parked socket must be the same one, not a third source",
    );
    sock_back.close(None).await?;
    Ok(())
}

/// Datagram boundaries survive the relay, in both directions.
///
/// This is the property the whole datagram framing exists for, and the one a
/// byte splice would silently destroy: two client datagrams sent back to back
/// must arrive at the target as two packets, and their two echoes must arrive at
/// the client as two frames. Coalescing shows up here as a single frame whose
/// length is the sum — the target echoes what it received, so a merged pair
/// cannot come back split.
///
/// The two payloads have different lengths on purpose: a merged pair would be
/// read as one datagram of the combined length, which no assertion below can
/// mistake for a pass.
#[tokio::test]
async fn cluster_vless_udp_relay_preserves_datagram_boundaries() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-udp-boundary-psk";
    let (target_addr, sources) = spawn_echo_udp_target().await?;

    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_cluster_node(PSK, 2, peers, Duration::from_secs(4), None, None).await?;

    // Park a VLESS-UDP session on the home so the edge has something to relay.
    let (mut sock_home, issued) = connect_ws_h1(home.listen_addr, "/vless", None, true).await?;
    let session_id = issued.context("the home must mint a resume id")?;
    sock_home
        .send(WsMessage::Binary(vless_udp_request(CLUSTER_VLESS_UUID, target_addr, b"seed")?))
        .await?;
    assert_eq!(read_vless_udp_datagram(&mut sock_home).await?.as_slice(), b"seed");
    sock_home.close(None).await?;
    drop(sock_home);
    wait_for_park(&home, session_id).await?;

    // Resume through the edge, then send two datagrams inside one WebSocket
    // frame — the tightest coalescing the client framing allows.
    let (mut socket, echoed_id) =
        connect_ws_h1(edge.listen_addr, "/vless", Some(session_id), true).await?;
    assert_eq!(echoed_id, Some(session_id), "the relay must echo the home's parked id");
    socket
        .send(WsMessage::Binary(vless_udp_request(CLUSTER_VLESS_UUID, target_addr, b"first")?))
        .await?;
    assert_eq!(read_vless_udp_datagram(&mut socket).await?.as_slice(), b"first");

    let mut both = BytesMut::new();
    both.put_u16(b"second".len() as u16);
    both.extend_from_slice(b"second");
    both.put_u16(b"third-datagram".len() as u16);
    both.extend_from_slice(b"third-datagram");
    socket.send(WsMessage::Binary(both.freeze())).await?;

    let echoed = read_vless_udp_datagrams(&mut socket, 2).await?;
    assert_eq!(
        echoed,
        vec![b"second".to_vec(), b"third-datagram".to_vec()],
        "two datagrams sent in one frame must arrive as two, byte-exact and in order",
    );
    assert_eq!(sources.lock().await.len(), 1, "every datagram rode the one parked socket",);
    socket.close(None).await?;
    Ok(())
}

/// A VLESS-**TCP** command presenting an id the home parked as **VLESS-UDP** must
/// not cost the home that park.
///
/// Cross-shape id reuse is a client that dialled TCP on a carrier whose previous
/// incarnation was UDP or mux — VLESS multiplexes all three onto one path, so
/// the id alone cannot say which. The home's ack tells the edge which shape it
/// is holding, and a `Tcp` command on a UDP-shaped park therefore releases the
/// relay *before* the USER frame that would make the home call
/// `take_for_resume`. Two further non-consuming probes back that up on the home
/// itself — the phase-1 one and the phase-2 one immediately before the take — so
/// no path can destroy the park while refusing it.
///
/// The echoed id is the home's, deliberately, and that is the visible cost of
/// deciding the shape this way: the `101` goes out while the relay is still
/// admitted, before the edge has read a single client byte. It is bounded and
/// non-destructive — the client comes back with the home's id, the home still
/// holds the park, and this edge serves it locally again — where the
/// alternatives are worse: withholding the id from every VLESS upgrade would
/// give up continuity for the commands that *can* be relayed, and delaying the
/// `101` until the first frame would break the upgrade handshake itself.
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

    // Same id, TCP command, through the edge. The home acks with the park's
    // shape, the edge sees a `Tcp` command needs a byte-stream upstream and
    // releases the relay without ever attesting a user — so this is served
    // locally and works, and nothing was consumed.
    let (mut socket, echoed_id) =
        connect_ws_h1(edge.listen_addr, "/vless", Some(session_id), true).await?;
    assert_eq!(
        echoed_id,
        Some(session_id),
        "an admitted relay echoes the home's id, even on the path that later releases it",
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

/// A VLESS **mux** command on a *byte-stream* park releases the mesh relay the
/// edge had already opened, serves its sub-connections directly, and leaves the
/// home's park intact.
///
/// This is the edge-side half of the same invariant the test above pins from the
/// home side, and the only place it can be exercised: the home holds a
/// `Parked::Tcp` here, so phase 1 legitimately admits the relay and the edge
/// really does take a mesh upstream before it can know what the client wants.
/// Only when the first frame parses as `VlessCommand::Mux` does it learn that
/// the upstream shape is wrong — a mux bundle is not a byte-stream park — and it
/// must get out *before* the USER frame, which is what would make the home
/// consume its park.
///
/// It also pins the scope rule for sub-connections: a mux session **this node
/// establishes** dials its own sub-connections, so the one below reaches its
/// target from the edge, on a socket the edge dialled itself. That rule is about
/// where a *fresh* mux lives and is unchanged; a mux park that already exists on
/// another node is a different question, and
/// [`cluster_vless_mux_survives_edge_switch`] answers it — there the frame layer
/// runs on the home and every sub-connection stays there.
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

/// A VLESS-**mux** session migrates across an edge switch: the whole bundle —
/// one TCP and one UDP sub-connection — keeps its upstreams on the home while a
/// carrier on a different node, with a different path and a different
/// credential, drives it.
///
/// Two counters carry the guarantee, one per sub-connection kind, and both are
/// the same probe: a fresh upstream would show up as a second accept on the TCP
/// echo target and a second source port on the UDP one. Neither may move.
///
/// The three legs are the three claims:
///
/// 1. **home** — a mux with both sub-connection kinds, parked as one
///    `Parked::VlessMux` under the id the home minted.
/// 2. **edge** — the same id on `/vless-edge` under `EDGE_VLESS_UUID`, a
///    credential the home has never heard of. The home acks `MeshShape::VlessMux`,
///    the edge keeps the relay and forwards the client's mux frame stream
///    verbatim; the home runs the frame layer over the bundle it parked. Both
///    sub-connections answer on their original sockets, which is what proves the
///    bundle re-attached whole rather than being re-dialled.
/// 3. **home again** — the bundle is re-parked when the mesh carrier ends, so a
///    mux session survives more than one switch, exactly as the byte-stream and
///    VLESS-UDP ones do.
///
/// The relayed downlink is read with [`collect_streamed_mux_keep_payloads`]
/// rather than the direct helper: the edge forwards mesh chunks, so several mux
/// frames may share one WebSocket message.
#[tokio::test]
async fn cluster_vless_mux_survives_edge_switch() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-mux-switch-psk";
    let (tcp_addr, tcp_accepts) = spawn_echo_target().await?;
    let (udp_addr, udp_sources) = spawn_echo_udp_target().await?;

    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_vless_cluster_node(
        PSK,
        2,
        peers,
        Duration::from_secs(4),
        "/vless-edge",
        EDGE_VLESS_UUID,
    )
    .await?;

    // Session #1 on the home: sub-conn 1 is TCP, sub-conn 2 is UDP.
    let (mut sock_home, issued) = connect_ws_h1(home.listen_addr, "/vless", None, true).await?;
    let session_id = issued.context("the home must mint a resume id")?;
    let mut handshake = BytesMut::from(vless_mux_request(CLUSTER_VLESS_UUID)?.as_ref());
    handshake.extend_from_slice(&vless_mux_new_tcp_frame(1, tcp_addr, b"tcp-home"));
    handshake.extend_from_slice(&vless_mux_new_udp_frame(2, udp_addr, b"udp-home"));
    sock_home.send(WsMessage::Binary(handshake.freeze())).await?;
    let header = expect_binary_reply(&mut sock_home).await?;
    assert_eq!(header.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoes = collect_mux_keep_payloads(&mut sock_home, &[1, 2]).await?;
    assert_eq!(echoes[&1], b"tcp-home");
    assert_eq!(echoes[&2], b"udp-home");
    assert_eq!(tcp_accepts.load(Ordering::SeqCst), 1, "the home dials one TCP sub-conn");
    assert_eq!(udp_sources.lock().await.len(), 1, "the home binds one UDP sub-conn source");
    sock_home.close(None).await?;
    drop(sock_home);
    wait_for_park(&home, session_id).await?;

    // Session #2 via the edge, same id, different path and credential.
    let (mut sock_edge, echoed_id) =
        connect_ws_h1(edge.listen_addr, "/vless-edge", Some(session_id), true).await?;
    assert_eq!(
        echoed_id,
        Some(session_id),
        "a relayed session must echo the id the home parks under",
    );
    sock_edge
        .send(WsMessage::Binary(vless_mux_request(EDGE_VLESS_UUID)?))
        .await?;
    let header = expect_binary_reply(&mut sock_edge).await?;
    assert_eq!(header.as_ref(), &[VLESS_VERSION, 0x00]);
    sock_edge
        .send(WsMessage::Binary(vless_mux_keep_frame(1, b"tcp-edge")))
        .await?;
    sock_edge
        .send(WsMessage::Binary(vless_mux_keep_frame(2, b"udp-edge")))
        .await?;
    let echoes = collect_streamed_mux_keep_payloads(&mut sock_edge, &[1, 2]).await?;
    assert_eq!(echoes[&1], b"tcp-edge", "the relayed TCP sub-conn reaches its parked upstream");
    assert_eq!(echoes[&2], b"udp-edge", "the relayed UDP sub-conn reaches its parked upstream");
    assert_eq!(
        tcp_accepts.load(Ordering::SeqCst),
        1,
        "resume across the edge switch must reuse the parked TCP sub-conn, not re-dial it",
    );
    assert_eq!(
        udp_sources.lock().await.len(),
        1,
        "resume across the edge switch must reuse the parked UDP sub-conn's source port",
    );
    sock_edge.close(None).await?;
    drop(sock_edge);

    // The home re-parks the whole bundle once the mesh carrier ends.
    wait_for_park(&home, session_id).await?;
    let (mut sock_back, _) =
        connect_ws_h1(home.listen_addr, "/vless", Some(session_id), true).await?;
    sock_back
        .send(WsMessage::Binary(vless_mux_request(CLUSTER_VLESS_UUID)?))
        .await?;
    let header = expect_binary_reply(&mut sock_back).await?;
    assert_eq!(header.as_ref(), &[VLESS_VERSION, 0x00]);
    sock_back
        .send(WsMessage::Binary(vless_mux_keep_frame(1, b"tcp-back")))
        .await?;
    sock_back
        .send(WsMessage::Binary(vless_mux_keep_frame(2, b"udp-back")))
        .await?;
    let echoes = collect_mux_keep_payloads(&mut sock_back, &[1, 2]).await?;
    assert_eq!(echoes[&1], b"tcp-back");
    assert_eq!(echoes[&2], b"udp-back");
    assert_eq!(
        tcp_accepts.load(Ordering::SeqCst),
        1,
        "the re-parked TCP sub-conn must be the same socket, not a third dial",
    );
    assert_eq!(
        udp_sources.lock().await.len(),
        1,
        "the re-parked UDP sub-conn must be the same socket, not a third source",
    );
    sock_back.close(None).await?;
    Ok(())
}

/// A mux park that cannot be re-attached whole is refused whole: the relay is
/// reset and no part of the bundle is spliced.
///
/// A mux park is one session, not a bag of sockets — one registry entry, whose
/// sub-connections the client addresses by id — so the home decides *once*,
/// before it attaches anything, whether the bundle can be served.
/// `vless_mux::attach_parked` is total below that decision (every parked
/// sub-connection already carries both halves of its upstream, so none of them
/// can fail to re-attach), which leaves exactly one state a bundle can be in
/// that no splice can serve: holding no sub-connection at all.
///
/// The park has to be injected directly, because no code path produces one:
/// `harvest_into_parked` can prune a bundle down to nothing, and both callers —
/// the direct `try_park_vless_mux` and the home splice's own re-park — refuse to
/// register the result. That is the point of pinning it here: the guard is the
/// reason the invariant survives a future caller that forgets, and without it
/// the client is handed a mux whose parked ids answer nothing.
#[tokio::test]
async fn a_mux_park_that_cannot_be_reattached_whole_is_refused_whole() -> Result<()> {
    const PSK: &[u8] = b"cluster-e2e-vless-mux-whole-psk";
    let (echo_addr, echo_accepts) = spawn_echo_target().await?;
    let (home, _user) =
        spawn_cluster_node(PSK, 1, HashMap::new(), Duration::from_secs(4), None, None).await?;
    let peers = HashMap::from([(ShardId::new(1).unwrap(), home.mesh_addr)]);
    let (edge, _) = spawn_vless_cluster_node(
        PSK,
        2,
        peers,
        Duration::from_secs(4),
        "/vless-edge",
        EDGE_VLESS_UUID,
    )
    .await?;

    // A mux park with an empty bundle, owned by the label every node's VLESS
    // route carries — so the home's owner check passes and the refusal below is
    // the bundle's emptiness and nothing else.
    let owner: Arc<str> = Arc::from("cluster-vless");
    let session_id = home
        .registry
        .mint_session_id()
        .context("the home registry must mint a resume id")?;
    home.registry.park(
        session_id,
        Parked::VlessMux(ParkedVlessMux {
            sub_conns: HashMap::new(),
            buffer: BytesMut::new(),
            user: VlessUser::new(CLUSTER_VLESS_UUID.into(), Arc::clone(&owner), None, None)?,
            owner: Arc::clone(&owner),
            user_counters: home_user_counters(&owner),
        }),
    );

    // The edge's OPEN is admitted (the shape is a mux park and the command is a
    // mux command), so the refusal happens in phase 2, after the USER frame — the
    // one place it can, since the bundle's contents are only visible once the
    // park is taken. The client is authenticated by then, so it gets the VLESS
    // response header the edge had already queued and then a close, rather than a
    // fresh local mux.
    let (mut socket, _) =
        connect_ws_h1(edge.listen_addr, "/vless-edge", Some(session_id), true).await?;
    socket
        .send(WsMessage::Binary(vless_mux_request(EDGE_VLESS_UUID)?))
        .await?;
    // A `New` frame is what discriminates a refused relay from a spliced one. A
    // `Keep` on a missing id is silently dropped by any mux, refused or not, but
    // a `New` reaches `open_tcp_sub` on the home the moment the splice is live —
    // so the echo target's accept counter and the silence below both flip
    // together if the bundle is ever admitted.
    socket
        .send(WsMessage::Binary(vless_mux_new_tcp_frame(9, echo_addr, b"never-arrives")))
        .await?;
    // Silence is the assertion: no mux frame may come back, because nothing was
    // attached. Bounded rather than read-to-EOF because a relay refused in phase
    // 2 fails the edge's *next* mesh operation, which on a client that has
    // stopped sending is its reader task rather than the carrier.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
    let mut seen_header = false;
    loop {
        match tokio::time::timeout_at(deadline, socket.next()).await {
            // Nothing more came: the relay spliced nothing.
            Err(_) | Ok(None) => break,
            Ok(Some(message)) => match message? {
                WsMessage::Close(_) => break,
                WsMessage::Binary(bytes) if !seen_header => {
                    assert_eq!(
                        bytes.as_ref(),
                        &[VLESS_VERSION, 0x00],
                        "the only thing a refused relay may have emitted is the response header \
                         the edge queued before the refusal reached it",
                    );
                    seen_header = true;
                },
                WsMessage::Binary(bytes) => {
                    bail!("a refused mux park must splice nothing, got {} bytes", bytes.len())
                },
                _ => {},
            },
        }
    }
    drop(socket);
    assert_eq!(
        echo_accepts.load(Ordering::SeqCst),
        0,
        "a refused mux park must never reach the frame layer, so no sub-connection is opened",
    );

    // Nothing to put back: an empty bundle is worth no registry slot, which is
    // the same rule `MuxState::is_parkable` applies on the direct path.
    assert!(
        !home.registry.has_park(session_id),
        "an unusable mux park must not be left behind after it is refused",
    );

    // The operator-visible half of the same guarantee. Silence on the wire tells
    // a client nothing was spliced; only this counter tells whoever runs the
    // cluster *why*, and it is the reason string — not just the count — that has
    // to hold, since it is what the `HELP` text on
    // `outline_ss_mesh_relay_rejected_total` documents and what an alert would
    // match on. Read off the home: the refusal is the home's, and the edge's own
    // recorder is a different one.
    let rendered = home.metrics.render_prometheus();
    assert_eq!(
        mesh_relay_rejected(&rendered, "park_incomplete"),
        1,
        "an unservable mux bundle must be counted under its own reason:\n{rendered}",
    );
    Ok(())
}

/// Reads `outline_ss_mesh_relay_rejected_total{reason="..."}` out of a rendered
/// scrape, treating an absent series as `0` — Prometheus counters are only
/// emitted once incremented.
fn mesh_relay_rejected(rendered: &str, reason: &str) -> u64 {
    let needle = format!("outline_ss_mesh_relay_rejected_total{{reason=\"{reason}\"}}");
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(&needle))
        .map_or(0, |value| value.trim().parse().expect("a rendered counter value is an integer"))
}

/// Sums every rendered series of `metric` whose label set contains all of
/// `labels`, treating no matching series as `0`.
///
/// Partial label matching is what makes this usable on the mesh counters, whose
/// label sets carry a dimension the assertion does not care about — a relay's
/// `close` reason, say — and it also keeps the assertion honest if a new
/// dimension is added later: a series that stops matching would read as `0`
/// rather than silently keep passing.
fn metric_sum(rendered: &str, metric: &str, labels: &[(&str, &str)]) -> u64 {
    rendered
        .lines()
        .filter_map(|line| line.strip_prefix(metric)?.strip_prefix('{'))
        .filter_map(|rest| rest.split_once('}'))
        .filter(|(label_set, _)| {
            labels
                .iter()
                .all(|(name, value)| label_set.contains(&format!("{name}=\"{value}\"")))
        })
        .map(|(_, value)| {
            value
                .trim()
                .parse::<u64>()
                .expect("a rendered counter value is an integer")
        })
        .sum()
}

/// `outline_ss_mesh_bytes_total{role="home",direction=…,transport="tcp"}` off a
/// rendered scrape.
///
/// `direction="down"` reading zero fleet-wide was the symptom a relay that had
/// never worked hid behind, which is why it is asserted rather than inferred
/// from a working round trip.
fn mesh_bytes(rendered: &str, direction: &str) -> u64 {
    metric_sum(
        rendered,
        "outline_ss_mesh_bytes_total",
        &[("role", "home"), ("direction", direction), ("transport", "tcp")],
    )
}

/// `outline_ss_orphan_resume_cross_protocol_total{parked=…,resumed=…}` off a
/// rendered scrape: resume hits where the park and the carrier that claimed it
/// were authenticated under different proxy protocols.
///
/// Counted on the node that owns the park, so a relayed crossing lands on the
/// **home** — which is also the only node that can know both labels.
fn cross_protocol_resumes(rendered: &str, parked: &str, resumed: &str) -> u64 {
    metric_sum(
        rendered,
        "outline_ss_orphan_resume_cross_protocol_total",
        &[("parked", parked), ("resumed", resumed)],
    )
}

/// `outline_ss_mesh_relay_outcome_total{outcome="…"}` off a rendered scrape,
/// summed over the `close` dimension.
fn mesh_relay_outcome(rendered: &str, outcome: &str) -> u64 {
    metric_sum(rendered, "outline_ss_mesh_relay_outcome_total", &[("outcome", outcome)])
}

/// Per-user counters for a park injected straight into a home's registry. The
/// registry only stores them; a relayed splice never increments them (the edge
/// counts), so a throwaway recorder's handle for the right label will do.
fn home_user_counters(owner: &Arc<str>) -> Arc<crate::metrics::PerUserCounters> {
    let config = sample_config((Ipv4Addr::LOCALHOST, 0).into());
    Metrics::new(&config).user_counters(owner)
}

/// Throttle detection on a relayed SS-TCP session, end to end. With padding +
/// throttle detection enabled on a dedicated path, a client that stalls its
/// downlink read while the home floods it through the mesh makes the edge's
/// client-facing send block; the edge detects the stall and injects an `OCTL`
/// cover frame, which the client decodes as `ThrottleSwitchUplink`.
///
/// The detection is **local to the edge**, and no `THROTTLE_HINT` datagram is
/// involved on any carrier any more: with client crypto terminating on the edge,
/// the node that owns the throttled last mile is also the node that owns the
/// padded writer, so it signals its own client directly. The mesh hint went with
/// the v4 relay it belonged to, receiver included — the mesh carries no control
/// datagrams at all now.
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
/// The pieces are covered deterministically elsewhere: the rate-based window by
/// the `throughput_monitor` tests, and the signal→OCTL half by the `ws_writer`
/// tests. The edge→home THROTTLE_HINT datagram itself is gone with the v4 relay
/// — every edge now terminates the client's crypto and signals its own client
/// directly.
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
        // Floor off: this timing-driven e2e drives the stall directly and the
        // flood-throttled delivery rate is not what it asserts on.
        throttle_min_bytes_per_sec: 0,
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
