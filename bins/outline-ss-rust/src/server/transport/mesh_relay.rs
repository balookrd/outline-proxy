//! Home-side mesh relay: accept relayed carriers from edge peers and serve them
//! through the existing accept path.
//!
//! A relayed session arrives as a QUIC stream carrying an [`OpenHeader`] plus
//! the still-encrypted application bytes. We wrap the stream in a
//! [`MeshCarrier`] (a `WsSocket`) and hand it to the same `run_tcp_relay` /
//! `run_vless_relay` used for a direct carrier — so crypto, upstream and
//! park/unpark behave identically. The home authenticates the user from the
//! relayed stream itself (SS salt / VLESS UUID); the header only carries the
//! resume id, capabilities, path and client-address hint.
//!
//! Resume: the header's session id is both the requested resume id and the
//! issued id — the home parks under the id the client already holds (there is
//! no HTTP response over the mesh to echo a fresh one). See `docs/CLUSTER.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::extract::ws::WebSocketUpgrade;
use axum::response::Response;
use outline_wire::cluster::ShardId;
use quinn::{RecvStream, SendStream, VarInt};
use tracing::{debug, warn};

use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    CarrierKind, CloseReason, MeshStream, OpenHeader, accept_relay,
};
use crate::server::resumption::SessionId;
use crate::server::shutdown::ShutdownSignal;
use crate::server::state::{
    RoutesSnapshot, Services, empty_transport_route, empty_vless_transport_route,
};

use super::carrier_padding;
use super::mesh_carrier::MeshCarrier;
use super::resume_headers::{EdgeResumeAdvert, ResumeContext, ResumeResponseEcho};
use super::tcp::{WsTcpRouteCtx, run_tcp_relay};
use super::vless::{VlessWsRouteCtx, run_vless_relay};
use super::ws_socket::{AxumWs, WsFrame, WsSocket};

/// Read granularity for the mesh→client direction on the edge.
const MESH_EDGE_CHUNK: usize = 256 * 1024;

/// Edge-side relay: splice a client carrier to a mesh relay stream, forwarding
/// the still-encrypted application bytes both ways. The edge does not decode
/// the SS/VLESS layer — it moves the WS binary payload verbatim (padding +
/// ciphertext) so the home strips both. Exactly one writer per direction, so
/// backpressure rides the QUIC / WS windows (mirrors [`super::mesh_carrier`]
/// on the home side). Validated end to end by the phase-8 test.
///
/// Known v1 limitation (h1/h2 client carriers only): the edge drops the
/// client's keepalive `Ping` rather than answering `Pong`, because a single
/// writer owns the client downlink and interleaving a control reply would
/// break that invariant. A fully idle session therefore relies on the client's
/// own reconnect; an H3 client carrier is unaffected (QUIC keep-alive holds
/// liveness and the client swallows its own Ping).
///
/// Health budget: `budget` bounds a single uplink write to the mesh. When the
/// home stops draining (hung or the cross-country interconnect stalls), the
/// QUIC send window fills and the write blocks; exceeding `budget` means a
/// stalled relay, so we reset the mesh stream with [`CloseReason::Budget`] and
/// fail — the client reconnects and gets a fresh session (the home parks the
/// upstream, which then TTL-expires). It measures *progress*, not RTT: a high
/// but flowing RTT keeps completing writes, so this only fires on a full stall.
/// It never false-fires on an idle session — an idle uplink blocks on `recv`,
/// not on a write. Pure-download stalls (no uplink to push) are left to the
/// mesh QUIC idle timeout. See `docs/CLUSTER.md` § Health budget.
pub(in crate::server::transport) async fn edge_relay<T: WsSocket>(
    client: T,
    mut mesh_send: SendStream,
    mut mesh_recv: RecvStream,
    budget: Duration,
) -> Result<()> {
    let (mut reader, mut writer) = client.split_io();

    // Uplink: the ONLY writer to `mesh_send`.
    let uplink = async {
        while let Some(msg) = T::recv(&mut reader).await? {
            match T::classify(msg) {
                WsFrame::Binary(data) => {
                    match tokio::time::timeout(budget, mesh_send.write_all(&data)).await {
                        Ok(result) => result.context("mesh edge uplink write")?,
                        Err(_elapsed) => {
                            // Stalled past the budget: the home is not draining.
                            let _ = mesh_send.reset(VarInt::from_u32(CloseReason::Budget.code()));
                            bail!("mesh relay stalled past the health budget");
                        },
                    }
                },
                WsFrame::Close => break,
                // The edge does not interpret the carrier; drop control frames.
                WsFrame::Ping(_) | WsFrame::Pong | WsFrame::Text => {},
            }
        }
        let _ = mesh_send.finish();
        Ok::<(), anyhow::Error>(())
    };

    // Downlink: the ONLY writer to the client `writer`.
    let downlink = async {
        while let Some(chunk) = mesh_recv
            .read_chunk(MESH_EDGE_CHUNK, true)
            .await
            .context("mesh edge downlink read")?
        {
            T::send(&mut writer, T::binary_msg(chunk.bytes))
                .await
                .context("edge client downlink write")?;
        }
        T::finish(&mut writer).await;
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

/// Describes a carrier the edge is about to relay to its home. Bundled so the
/// TCP and VLESS upgrade call sites stay readable.
pub(in crate::server::transport) struct EdgeRelay {
    /// Home shard the resume id decoded to.
    pub(in crate::server::transport) shard: ShardId,
    /// Raw client resume advertisement to carry in the OPEN header.
    pub(in crate::server::transport) advert: EdgeResumeAdvert,
    /// Carrier kind (already resolved to a Tcp/Udp leg for combined-SS).
    pub(in crate::server::transport) carrier: CarrierKind,
    /// Request path, for the home's padding-scheme selection and routing.
    pub(in crate::server::transport) path: Arc<str>,
    /// Client address hint (logging / routing scope on the home).
    pub(in crate::server::transport) peer_addr: SocketAddr,
    /// HTTP version of the client carrier (metrics label).
    pub(in crate::server::transport) protocol: Protocol,
    /// Application protocol of the carrier (metrics label).
    pub(in crate::server::transport) app_protocol: AppProtocol,
    /// Short carrier name for session-teardown logging (`"tcp"` / `"vless"`).
    pub(in crate::server::transport) kind: &'static str,
}

/// Edge side: relay a foreign-shard carrier to its home over the mesh.
///
/// The mesh relay is opened **before** the WebSocket `101` handshake so the
/// echoed session id reflects the real outcome. On success the returned
/// response upgrades the client carrier and splices it byte-for-byte to the
/// home, echoing the id the client already holds (the home parks the upstream
/// under exactly that id — continuity across the edge switch). On failure the
/// [`WebSocketUpgrade`] is handed back so the caller serves a fresh local
/// session instead (this edge becomes the new home and mints its own id).
pub(in crate::server::transport) async fn try_relay_edge(
    ws: WebSocketUpgrade,
    cluster: &ClusterCtx,
    metrics: &Arc<Metrics>,
    relay: EdgeRelay,
) -> std::result::Result<Response, WebSocketUpgrade> {
    let EdgeRelay {
        shard,
        advert,
        carrier,
        path,
        peer_addr,
        protocol,
        app_protocol,
        kind,
    } = relay;
    let header = OpenHeader {
        carrier,
        session_id: *advert.session_id.as_bytes(),
        resume_capable: advert.resume_capable,
        ack_prefix: advert.ack_prefix,
        symmetric_replay: advert.symmetric_replay,
        client_down_acked: advert.down_acked,
        path: path.to_string(),
        peer_addr: Some(peer_addr),
    };
    let pooled = match cluster.pool.open_relay(shard, &header).await {
        Ok(pooled) => pooled,
        Err(error) => {
            debug!(
                ?error,
                shard = shard.get(),
                "mesh relay open failed; serving a fresh local session",
            );
            return Err(ws);
        },
    };
    let session = metrics.open_websocket_session(Transport::Tcp, protocol, app_protocol);
    let budget = cluster.relay_budget;
    // Continuity: echo the id the client presented — the home parks the relayed
    // upstream under exactly that id, so the client keeps resuming it.
    let echo = ResumeResponseEcho {
        session_id: Some(advert.session_id),
        ..Default::default()
    };
    let mut response = ws.on_upgrade(move |socket| async move {
        // Hold the pool permit for the relay's whole lifetime (drops here).
        let (send, recv, _permit) = pooled.into_parts();
        let result = edge_relay::<AxumWs>(AxumWs(socket), send, recv, budget).await;
        super::finish_ws_session(session, result, kind);
    });
    echo.apply(response.headers_mut());
    Ok(response)
}

/// Accepts relayed connections from edge peers until the endpoint closes or the
/// server shuts down. One task per peer connection; one task per relayed
/// session on it.
pub(in crate::server) async fn run_mesh_listener(
    cluster: Arc<ClusterCtx>,
    services: Arc<Services>,
    routes: RoutesSnapshot,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    loop {
        tokio::select! {
            accepted = cluster.endpoint.accept() => {
                match accepted {
                    Some(Ok(conn)) => {
                        let services = Arc::clone(&services);
                        let routes = Arc::clone(&routes);
                        tokio::spawn(handle_mesh_connection(conn, services, routes));
                    },
                    Some(Err(error)) => debug!(?error, "mesh peer connection failed"),
                    None => break, // endpoint closed
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
    Ok(())
}

/// Serves every relay stream a peer opens on `conn` until it closes.
async fn handle_mesh_connection(
    conn: quinn::Connection,
    services: Arc<Services>,
    routes: RoutesSnapshot,
) {
    // Ends when the peer closes the connection (accept_relay errors).
    while let Ok((header, stream)) = accept_relay(&conn).await {
        let services = Arc::clone(&services);
        let routes = Arc::clone(&routes);
        tokio::spawn(async move {
            if let Err(error) = serve_relayed(header, stream, &services, &routes).await {
                debug!(?error, "relayed session ended with error");
            }
        });
    }
}

/// Dispatches one relayed carrier into the matching accept path.
async fn serve_relayed(
    header: OpenHeader,
    stream: MeshStream,
    services: &Services,
    routes: &RoutesSnapshot,
) -> Result<()> {
    let carrier = MeshCarrier::new(stream);
    let path: Arc<str> = Arc::from(header.path.as_str());
    let padding = carrier_padding::scheme_for_path(&path);
    let session_id = SessionId::from_bytes(header.session_id);
    // The home parks under the id the client already holds; there is no HTTP
    // response over the mesh to hand back a freshly minted one.
    let resume = ResumeContext {
        requested_resume: Some(session_id),
        issued_session_id: Some(session_id),
        ack_prefix_requested: header.ack_prefix,
        symmetric_replay_requested: header.symmetric_replay,
        client_acked_offset: header.client_down_acked,
    };
    let peer_addr = header.peer_addr;

    match header.carrier {
        CarrierKind::SsTcp => {
            let route = {
                let snap = routes.load();
                snap.tcp.get(&*path).cloned().unwrap_or_else(empty_transport_route)
            };
            let route_ctx = WsTcpRouteCtx {
                users: Arc::clone(&route.users),
                protocol: Protocol::Http3,
                path: Arc::clone(&path),
                candidate_users: Arc::clone(&route.candidate_users),
                peer_user_cache: Arc::clone(&route.peer_user_cache),
                padding,
            };
            run_tcp_relay(carrier, &services.tcp_server, &route_ctx, resume, peer_addr).await
        },
        CarrierKind::VlessTcp => {
            let route = {
                let snap = routes.load();
                snap.vless
                    .get(&*path)
                    .cloned()
                    .unwrap_or_else(empty_vless_transport_route)
            };
            let route_ctx = VlessWsRouteCtx {
                users: Arc::clone(&route.users),
                protocol: Protocol::Http3,
                path: Arc::clone(&path),
                candidate_users: Arc::clone(&route.candidate_users),
                padding,
                peer: peer_addr.map(|addr| addr.ip()),
            };
            run_vless_relay(carrier, &services.vless_server, &route_ctx, resume).await
        },
        CarrierKind::SsUdp | CarrierKind::VlessUdp => {
            warn!("UDP mesh relay is not yet supported; dropping relayed session");
            bail!("UDP mesh relay not yet supported")
        },
    }
}
