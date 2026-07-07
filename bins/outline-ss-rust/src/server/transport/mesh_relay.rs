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

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use quinn::{RecvStream, SendStream};
use tracing::{debug, warn};

use crate::metrics::Protocol;
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{CarrierKind, MeshStream, OpenHeader, accept_relay};
use crate::server::resumption::SessionId;
use crate::server::shutdown::ShutdownSignal;
use crate::server::state::{
    RoutesSnapshot, Services, empty_transport_route, empty_vless_transport_route,
};

use super::carrier_padding;
use super::mesh_carrier::MeshCarrier;
use super::resume_headers::ResumeContext;
use super::tcp::{WsTcpRouteCtx, run_tcp_relay};
use super::vless::{VlessWsRouteCtx, run_vless_relay};
use super::ws_socket::{WsFrame, WsSocket};

/// Read granularity for the mesh→client direction on the edge.
const MESH_EDGE_CHUNK: usize = 256 * 1024;

/// Edge-side relay: splice a client carrier to a mesh relay stream, forwarding
/// the still-encrypted application bytes both ways. The edge does not decode
/// the SS/VLESS layer — it moves the WS binary payload verbatim (padding +
/// ciphertext) so the home strips both. Exactly one writer per direction, so
/// backpressure rides the QUIC / WS windows (mirrors [`super::mesh_carrier`]
/// on the home side). Validated end to end by the phase-8 test.
#[allow(dead_code)] // invoked by the edge accept branch in phase 5c-3b.
pub(in crate::server::transport) async fn edge_relay<T: WsSocket>(
    client: T,
    mut mesh_send: SendStream,
    mut mesh_recv: RecvStream,
) -> Result<()> {
    let (mut reader, mut writer) = client.split_io();

    // Uplink: the ONLY writer to `mesh_send`.
    let uplink = async {
        while let Some(msg) = T::recv(&mut reader).await? {
            match T::classify(msg) {
                WsFrame::Binary(data) => {
                    mesh_send.write_all(&data).await.context("mesh edge uplink write")?;
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
