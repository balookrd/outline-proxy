//! Plaintext VLESS mux splice.

use super::close::{
    DownlinkEnd, SpliceEnd, SpliceFault, SpliceOutcome, StreamClose, resolve_close_intent,
    splice_end,
};
use super::home::refuse_relay;
use super::splice_udp::RELAYED_PATH;
use super::{CLOSE_NONE, MESH_HOME_SPLICE_CHUNK};
use crate::metrics::Protocol;
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::CloseIntent;
use crate::server::cluster::mesh::CloseReason;
use crate::server::cluster::mesh::MeshStream;
use crate::server::cluster::mesh::OpenHeader;
use crate::server::cluster::mesh::UpstreamAckFrame;
use crate::server::resumption::Parked;
use crate::server::resumption::ParkedVlessMux;
use crate::server::resumption::SessionId;
use crate::server::state::Services;
use crate::server::transport::vless_mux;
use crate::server::transport::vless_mux::MuxAccounting;
use crate::server::transport::vless_mux::MuxRouteCtx;
use crate::server::transport::vless_mux::MuxServerCtx;
use anyhow::Context;
use anyhow::Result;
use bytes::Bytes;
use outline_wire::padding::PaddingScheme;
use quinn::VarInt;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tracing::debug;
use tracing::warn;

/// Splices a relayed plaintext VLESS-mux session onto the bundle of
/// sub-connections it parked.
///
/// # What crosses the mesh
///
/// The client's own **mux frame stream**, verbatim, as a transparent byte
/// stream. The edge terminates the client's carrier and the VLESS request
/// header, but it does not parse mux frames — so the body arriving here is
/// exactly what the client emitted, and this node is the mux endpoint. Nothing
/// needs a mesh-level delimiter: a mux frame carries its own length prefix, and
/// a UDP sub-connection's datagram boundary is the frame boundary (one `Keep`
/// frame is one datagram, target included), so the atomicity that
/// [`super::super::cluster::mesh::datagram`] framing exists to protect is
/// already on the wire. See the `cluster::mesh::frame` module doc for what was
/// rejected.
///
/// # How each sub-connection re-attaches
///
/// It does not move. [`vless_mux::attach_parked`] re-spawns one reader task per
/// parked sub-connection against this splice's downlink channel instead of a
/// WebSocket writer — a TCP sub-connection keeps its `OwnedWriteHalf` and gets
/// its `OwnedReadHalf` back, a UDP one keeps its `Arc<UdpSocket>` and its
/// `default_target` — so not one upstream socket is reopened and every source
/// port survives the node switch. The mux's half-decoded inbound frame rides
/// through in `MuxState::buffer`.
///
/// Sub-connections opened *inside* a relayed mux are therefore dialled from
/// **this** node, not the edge: the mux frame layer runs here, so `New` frames
/// reach `open_tcp_sub` / `open_udp_sub` with this node's DNS cache and outbound
/// settings, under the fwmark of the `VlessUser` the park carries. That is the
/// same rule every other relayed shape follows — the home owns the session's
/// upstreams — and the alternative would split one mux bundle across two nodes,
/// leaving nothing either of them could park.
///
/// # Whole or nothing
///
/// A mux park is one session, not a bag of sockets: `Parked::VlessMux` is a
/// single registry entry and the client addresses every sub-connection in it by
/// id. So the bundle is admitted whole or refused whole. The one precondition —
/// it still holds a sub-connection — is checked **before** `attach_parked`, and
/// a bundle that fails it is refused with nothing consumed from it;
/// `attach_parked` is total below that point, so no partial attach exists to
/// guard against.
///
/// # Accounting
///
/// Per-user bytes are counted on the edge, once, exactly as in the three
/// splices above — here through [`MuxAccounting::OnTheEdge`], which silences the
/// per-sub-connection counters the direct mux path uses. The park's
/// `user_counters` ride through untouched so a later *direct* resume on this
/// node keeps counting where it left off.
///
/// # Continuity
///
/// An `ack_prefix` OPEN gets its [`UpstreamAckFrame`] — present exactly when the
/// flag is set, on every shape — reporting `0`: a mux session has no single
/// uplink byte offset to be short of, its upstreams being many sockets behind a
/// frame layer. The edge emits no client-facing Ack-Prefix frame for a mux
/// either, matching the direct mux path, which has never emitted one.
/// `symmetric_replay` likewise has nothing to replay: no mux path keeps a
/// downlink ring.
///
/// Which is why a **downlink fault refuses the park** here, where the byte-stream
/// splice keeps it: with nothing to replay from, a bundle whose uplink was
/// cancelled mid-frame cannot be handed on as continuable. See the `deny_park` on
/// the downlink-fault arm below.
pub(super) async fn splice_plaintext_vless_mux(
    stream: MeshStream,
    parked: ParkedVlessMux,
    header: &OpenHeader,
    session_id: SessionId,
    cluster: &ClusterCtx,
    services: &Services,
) -> Result<()> {
    let MeshStream { mut send, mut recv } = stream;
    let registry = &services.orphan_registry;
    let vless = &services.vless_server;
    let owner = Arc::clone(&parked.owner);

    // Whole or nothing, checked before anything is attached. An empty bundle is
    // the one state a park can reach that no splice can serve — `harvest_into_parked`
    // prunes sub-connections whose reader already exited — and it is worth
    // nothing to a later carrier either, so it is dropped rather than put back
    // (the direct park path refuses to create one for the same reason, see
    // `MuxState::is_parkable`).
    if parked.sub_conns.is_empty() {
        cluster.metrics.record_mesh_relay_rejected("park_incomplete");
        // Not a `miss`: a park *was* found under this id and taken, and an empty
        // bundle is worth nothing to a later carrier, so it is dropped rather
        // than put back. See the `unusable` outcome's HELP text.
        cluster.metrics.record_mesh_relay_outcome("unusable", CLOSE_NONE);
        warn!(
            user = %owner,
            "refusing a relayed VLESS-mux resume: the parked bundle holds no sub-connection to \
             re-attach",
        );
        refuse_relay(MeshStream { send, recv }, CloseReason::Abort);
        return Ok(());
    }

    // Uplink continuity, for symmetry with the other splices: present exactly
    // when the OPEN asked for it, and zero is the truthful answer. The bundle is
    // still untouched if this fails, so it goes back whole.
    if header.ack_prefix {
        let frame = UpstreamAckFrame { upstream_acked: 0 };
        if let Err(error) = send.write_all(&frame.encode()).await {
            cluster.metrics.record_mesh_relay_outcome("hit", CLOSE_NONE);
            if registry.enabled() {
                registry.park(session_id, Parked::VlessMux(parked));
            }
            return Err(
                anyhow::Error::new(error).context("sending the upstream-ack frame over the mesh")
            );
        }
    }

    // The mux frame layer runs here, so it needs this node's outbound context —
    // the same one the direct VLESS path hands it. `Protocol::Http3` and the
    // `mesh` path label stand in for the client-facing carrier the home does not
    // have; neither reaches a per-user series, because this mux does not count.
    let mux_server = MuxServerCtx {
        dns_cache: Arc::clone(&vless.dns_cache),
        prefer_ipv4_upstream: vless.prefer_ipv4_upstream,
        outbound_ipv6: vless.outbound_ipv6.clone(),
        metrics: Arc::clone(&vless.metrics),
    };
    let mux_route = MuxRouteCtx {
        protocol: Protocol::Http3,
        path: Arc::from(RELAYED_PATH),
    };
    // Bounded, like every other downlink fan-in on this node: the sub-connection
    // readers block on a full channel instead of growing it.
    let (tx, mut downlink_rx) = mpsc::channel::<Bytes>(vless.ws_data_channel_capacity);
    let mut mux = vless_mux::attach_parked(
        parked,
        tx.clone(),
        std::convert::identity,
        &vless.metrics,
        Protocol::Http3,
        MuxAccounting::OnTheEdge,
        // Plaintext mux frames over the mesh: the edge pads the client stream.
        PaddingScheme::disabled(),
        // The edge terminates VLESS and owes the client its response header.
        None,
    );

    let up_bytes = cluster.metrics.mesh_bytes_counter("home", "up", "tcp");
    let down_bytes = cluster.metrics.mesh_bytes_counter("home", "down", "tcp");
    let budget = cluster.relay_budget;
    let stop_downlink = Notify::new();

    let SpliceOutcome { end, stream_finished, observed_intent } = {
        let recv = &mut recv;
        let send = &mut send;
        let stop = &stop_downlink;
        let mux = &mut mux;
        let tx = &tx;
        let mux_server = &mux_server;
        let mux_route = &mux_route;
        let downlink_rx = &mut downlink_rx;

        // Uplink: mesh → the mux frame layer. Chunk boundaries are irrelevant —
        // `handle_client_bytes` buffers a partial frame and that buffer is what
        // a re-park hands on.
        let uplink = async move {
            loop {
                let chunk = match recv
                    .read_chunk(MESH_HOME_SPLICE_CHUNK, true)
                    .await
                    .context("relayed uplink read from the mesh")
                {
                    Ok(Some(chunk)) => chunk,
                    // The edge finished the stream: the client carrier is gone.
                    // Every sub-connection is deliberately left running — the
                    // caller harvests and re-parks the whole bundle.
                    Ok(None) => return Ok(()),
                    Err(error) => return Err(SpliceFault::mesh(error)),
                };
                up_bytes.increment(chunk.bytes.len() as u64);
                if let Err(error) = vless_mux::handle_client_bytes(
                    mux,
                    &chunk.bytes,
                    mux_server,
                    mux_route,
                    tx,
                    std::convert::identity,
                )
                .await
                {
                    // A malformed frame stream, or a downlink channel that is
                    // gone: the mux's frame buffer is desynchronised either way,
                    // so the bundle is not worth handing to a later carrier.
                    return Err(SpliceFault::upstream(
                        error.context("relaying vless mux frames from the mesh"),
                    ));
                }
            }
        };

        // Downlink: the sub-connections' frames → mesh. The ONLY writer to the
        // mesh stream. Frames go out whole, but need no mesh-level delimiter:
        // each already carries its own length prefix.
        let downlink = async move {
            loop {
                let frame = tokio::select! {
                    // Biased so a pending stop wins over one more frame: the
                    // uplink has ended, and a frame written into a stream the
                    // caller is about to close is worth nothing. Both branches
                    // are cancel-safe.
                    biased;
                    () = stop.notified() => return Ok(DownlinkEnd::Stopped),
                    // Never `None`: this scope's `tx` keeps a sender alive.
                    Some(frame) = downlink_rx.recv() => frame,
                    else => return Ok(DownlinkEnd::Stopped),
                };
                let len = frame.len();
                match tokio::time::timeout(budget, send.write_all(&frame)).await {
                    Ok(Ok(())) => {},
                    // A `ClientDone` stop lands here as a write failure, the same
                    // signal the other splices read: the client is finished, so
                    // the uplink goes on draining to its FIN while the downlink
                    // stands down.
                    Ok(Err(quinn::WriteError::Stopped(code)))
                        if CloseIntent::from_code(code.into_inner()) == CloseIntent::ClientDone =>
                    {
                        return Ok(DownlinkEnd::ClientDone);
                    },
                    Ok(Err(error)) => {
                        return Err(SpliceFault::mesh(
                            anyhow::Error::new(error).context("relayed downlink write to the mesh"),
                        ));
                    },
                    Err(_elapsed) => {
                        return Err(SpliceFault::stalled_mesh(anyhow::anyhow!(
                            "relayed downlink stalled past the health budget"
                        )));
                    },
                }
                down_bytes.increment(len as u64);
            }
        };

        tokio::pin!(uplink, downlink);
        let mut downlink_ended: Option<Result<DownlinkEnd, SpliceFault>> = None;
        loop {
            tokio::select! {
                result = &mut uplink => {
                    // The uplink is done, so the downlink stops at a frame
                    // boundary and is awaited rather than dropped — and because
                    // the uplink has already returned, a fault it reports here
                    // cancels nothing and may still hand the bundle on.
                    let downlink_end = match downlink_ended {
                        Some(ended) => ended,
                        None => {
                            stop.notify_one();
                            downlink.as_mut().await
                        },
                    };
                    break splice_end(result, downlink_end);
                },
                result = &mut downlink, if downlink_ended.is_none() => match result {
                    Ok(ended) => downlink_ended = Some(Ok(ended)),
                    // The downlink failed, so the whole relay is over and the
                    // uplink is dropped where it stands. `deny_park` is what
                    // makes that safe here — and it is deliberately **not** the
                    // trade `splice_plaintext_tcp` makes on the identical arm.
                    //
                    // That splice keeps its upstream across the very same
                    // cancellation because `write_uplink_chunk` credits
                    // `upstream_bytes_acked` byte by byte as the socket takes
                    // them, so the next carrier replays exactly the hole the
                    // cancellation left. A mux has none of that compensation:
                    // `upstream_acked` is `0` by construction, there is no
                    // downlink ring, and no client-facing Ack-Prefix frame is
                    // ever emitted. The cancelled uplink can be suspended inside
                    // a sub-connection's `write_all` — a partial application
                    // payload already handed to a TCP socket, its frame already
                    // removed from `MuxState::buffer` — or inside `open_tcp_sub`,
                    // losing a `New` frame so that sub-connection id would answer
                    // nothing for the rest of the session. Neither leaves a trace
                    // in the bundle that would be handed on.
                    //
                    // So a bundle whose uplink was cancelled at an unknown point
                    // is exactly as untrustworthy as the desynchronised frame
                    // buffer `SpliceFault::upstream` already refuses to park, and
                    // is refused the same way: the client re-establishes its mux
                    // instead of resuming one with a silent hole in it. Stopping
                    // the uplink cooperatively at a frame boundary — the shape
                    // the downlink uses — was the alternative, and it would have
                    // to wait on a sub-connection write that carries no budget
                    // while draining a downlink channel whose pump is already
                    // gone: a rare lost bundle traded for a relay that can hang.
                    Err(fault) => break SpliceOutcome {
                        end: fault.into_end().deny_park(),
                        stream_finished: false,
                        observed_intent: CloseIntent::CarrierEnded,
                    },
                },
            }
        }
    };

    let intent = resolve_close_intent(&end, observed_intent, &send);
    let reparks = end.reparks(intent);
    cluster
        .metrics
        .record_mesh_relay_outcome("hit", intent.metric_label());

    match end.stream_close(stream_finished, intent) {
        StreamClose::Reset(reason) => {
            let _ = send.reset(VarInt::from_u32(reason.code()));
        },
        StreamClose::Finish => {
            let _ = send.finish();
        },
    }

    if reparks && registry.enabled() {
        // Harvest and re-park the whole bundle, mirroring the direct path's
        // `try_park_vless_mux`, so a mux session survives more than one carrier
        // switch.
        //
        // The drain is load-bearing, not tidiness: `harvest_into_parked` awaits
        // each reader task after asking it to stop, and a reader blocked on a
        // full downlink channel only reaches its cancel arm once that send
        // completes. The direct path is safe because its WebSocket writer keeps
        // draining through the harvest; here the downlink pump has already
        // stopped, so the harvest has to drain the channel itself or deadlock.
        // The frames it discards are ones the carrier that is already gone would
        // never have carried.
        let parked = {
            let harvest = mux.harvest_into_parked(Arc::clone(&owner));
            tokio::pin!(harvest);
            loop {
                tokio::select! {
                    parked = &mut harvest => break parked,
                    _ = downlink_rx.recv() => {},
                }
            }
        };
        if parked.sub_conns.is_empty() {
            debug!(
                user = %owner,
                "not re-parking a relayed vless mux: no sub-connection survived the harvest",
            );
        } else {
            debug!(
                user = %owner,
                sub_conns = parked.sub_conns.len(),
                "re-parking a relayed vless mux after the mesh carrier ended",
            );
            registry.park(session_id, Parked::VlessMux(parked));
        }
    } else {
        // Nothing worth parking (the frame stream broke, the client said it was
        // done, or resumption is off): half-close every TCP sub-connection so its
        // target sees the end of the request body, and drop the rest.
        debug!(user = %owner, ?intent, "closing a relayed vless mux instead of re-parking it");
        mux.shutdown().await;
    }

    match end {
        SpliceEnd::Graceful { .. } => Ok(()),
        SpliceEnd::Faulted { error, .. } => Err(error),
    }
}
