use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, warn};

use outline_wire::padding::PaddingScheme;

use crate::{
    metrics::{AppProtocol, Metrics, Protocol, TcpUpstreamGuard},
    protocol::vless::{self, VlessUser},
};

use super::super::super::{
    abort::AbortOnDrop,
    connect::connect_tcp_target,
    relay::{GREEDY_DRAIN_TARGET, UpstreamRead},
    resumption::{Parked, ParkedProtocol, ParkedTcp, ResumeOutcome, SessionId},
};
use super::super::carrier_padding;
use super::super::upstream_source::{
    HarvestedUpstream, MeshUpstream, MeshUpstreamHalves, MeshUpstreamSetup, UpstreamWriter,
};
use super::ctx::{
    TcpUpstream, UpstreamSession, VlessFrameError, VlessRelayOutcome, VlessRelayState,
    VlessRelayTaskOutput, VlessWsOutbound, VlessWsRouteCtx, VlessWsServerCtx,
};

/// Graceful close of a TCP upstream that was extracted from
/// [`UpstreamSession::Tcp`] but never made it into the orphan
/// registry (park aborted, harvest race, no authenticated user).
/// Mirrors the cleanup that `run_vless_relay` runs on the unparked
/// path so that `try_park_*` early-returns don't degrade FIN→RST or
/// drop the gauge silently.
///
/// Covers a mesh upstream too: `shutdown` is a QUIC FIN there, which is what
/// tells the home this carrier is done, and the gauge is `None` because a
/// cluster edge never opened an upstream socket to count.
pub(super) async fn shutdown_unparked_tcp(
    mut writer: UpstreamWriter,
    guard: Option<TcpUpstreamGuard>,
) {
    writer.shutdown().await.ok();
    if let Some(guard) = guard {
        guard.finish();
    }
}

pub(super) async fn try_park_vless_tcp(
    state: &mut VlessRelayState,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    session_id: SessionId,
) -> bool {
    // A relayed (cluster-edge) session is never parked here: the upstream socket
    // lives on the home, which parks it under the id the client already holds.
    // Parking on the edge would register a session whose upstream this node does
    // not own, and would compete with the home's own park for the same id.
    // Checked before the harvest below so the still-running reader is left for
    // the caller's ordinary teardown. `run_vless_relay` cannot even reach here
    // for such a session (`edge_upstream` leaves `issued_session_id` unset), so
    // this is the second of three independent guards; `into_tcp` is the third.
    if let UpstreamSession::Tcp(tcp) = &state.upstream
        && tcp.writer.is_mesh()
    {
        return false;
    }
    let TcpUpstream {
        writer,
        reader_task,
        cancel,
        target_display,
        guard,
    } = match std::mem::replace(&mut state.upstream, UpstreamSession::None) {
        UpstreamSession::Tcp(tcp) => tcp,
        other => {
            // Shouldn't happen given the caller's match.
            state.upstream = other;
            return false;
        },
    };
    cancel.notify_one();
    let reader = match reader_task.into_inner().await {
        Ok(Ok(VlessRelayOutcome::Cancelled(HarvestedUpstream::Tcp(reader)))) => reader,
        // Unreachable: the mesh guard above returns before the harvest. Kept as
        // a refusal rather than a panic — nothing here can park a relayed
        // upstream, whichever way this state were reached.
        Ok(Ok(VlessRelayOutcome::Cancelled(HarvestedUpstream::Mesh))) => {
            shutdown_unparked_tcp(writer, guard).await;
            return false;
        },
        Ok(Ok(VlessRelayOutcome::Closed)) => {
            shutdown_unparked_tcp(writer, guard).await;
            return false;
        },
        Ok(Ok(VlessRelayOutcome::UdpCancelled)) => {
            // Should never fire on the TCP harvest path — the UDP
            // variant is reserved for `try_park_vless_udp_single`.
            // Treat as "not parking" to be safe.
            shutdown_unparked_tcp(writer, guard).await;
            return false;
        },
        Ok(Err(error)) => {
            debug!(?error, "vless relay task errored before park; not parking");
            shutdown_unparked_tcp(writer, guard).await;
            return false;
        },
        Err(join_error) => {
            warn!(?join_error, "vless relay task panicked while harvesting reader for park");
            shutdown_unparked_tcp(writer, guard).await;
            return false;
        },
    };
    let user = match state.authenticated_user.take() {
        Some(user) => user,
        None => {
            shutdown_unparked_tcp(writer, guard).await;
            return false;
        },
    };
    let user_counters = match state.user_counters.take() {
        Some(c) => c,
        None => {
            shutdown_unparked_tcp(writer, guard).await;
            state.authenticated_user = Some(user);
            return false;
        },
    };
    // Third guard against parking a relayed session: only a socket this node
    // owns can be handed to the registry, and only a real socket carries the
    // upstream-connection gauge the parked entry keeps alive. Unreachable — the
    // mesh guard at the top of this function already returned — but it ends the
    // upstream the way every other early return here does, so a future path into
    // it cannot degrade the FIN that helper exists to preserve.
    let (upstream_writer, upstream_guard) = match (writer, guard) {
        (UpstreamWriter::Tcp(writer), Some(guard)) => (writer, guard),
        (writer, guard) => {
            shutdown_unparked_tcp(writer, guard).await;
            return false;
        },
    };
    let owner = user.label_arc();
    let parked = ParkedTcp {
        upstream_writer,
        upstream_reader: reader,
        target_display,
        owner: Arc::clone(&owner),
        // Diagnostic only: no resume path branches on it, and a carrier of
        // either protocol may take this park (see [`ParkedProtocol`]).
        protocol: ParkedProtocol::Vless,
        user_counters,
        upstream_guard,
        // Move the per-session Ack-Prefix counter into the parked
        // entry so the v1.1 control-frame emit on the next resume
        // hit reports the cumulative upstream byte count this
        // session has produced — including bytes the previous
        // incarnation wrote to the upstream socket. The `Arc` is
        // moved (not cloned) so the relay state can no longer
        // observe further writes; subsequent writes go through the
        // resumed state's own counter (restored from this Arc on
        // the resume reattach).
        upstream_bytes_acked: Arc::clone(&state.upstream_bytes_acked),
        // v2 Symmetric Downlink Replay ring: move the per-session ring
        // into the parked entry so a subsequent resume hit can replay
        // the contiguous suffix `[client_acked_offset, total_sent)`.
        // `None` means v2 was never engaged on this session.
        downlink_ring: state.downlink_ring.take(),
    };
    let ring_diag = parked.downlink_ring.as_ref().map(|ring| {
        let g = ring.lock();
        (g.oldest_offset(), g.total_sent(), g.buffered_bytes())
    });
    let (ring_oldest, ring_total, ring_buffered) = ring_diag.unwrap_or((0, 0, 0));
    debug!(
        user = %owner,
        path = %route.path,
        ring_present = ring_diag.is_some(),
        ring_oldest_offset = ring_oldest,
        ring_total_sent = ring_total,
        ring_buffered_bytes = ring_buffered,
        "parking vless tcp upstream into orphan registry",
    );
    server.orphan_registry.park(session_id, Parked::Tcp(parked));
    // The original `VlessUser` is not preserved in the parked entry —
    // the next client stream re-runs UUID match against the route's
    // user list. Restore on the relay state so the caller's cleanup
    // drops it normally.
    state.authenticated_user = Some(user);
    true
}

pub(super) async fn establish_vless_tcp_upstream<Msg>(
    state: &mut VlessRelayState,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    outbound: VlessWsOutbound<'_, Msg>,
) -> Result<(), VlessFrameError>
where
    Msg: Send + 'static,
{
    let target = request.target.clone();
    let target_display = target.to_string();
    debug!(user = user.label(), path = %route.path, target = %target_display, "vless tcp target");

    // Cluster edge: the upstream lives on the home, which is still waiting to be
    // told *who* this session belongs to. Neither the local registry nor an
    // outbound connect is consulted — the home owns both, and the target parsed
    // above is deliberately ignored for the same reason a local resume hit
    // ignores it: the parked target is authoritative.
    if let Some(setup) = state.mesh_upstream.take() {
        attach_mesh_upstream(
            state,
            setup,
            request,
            user,
            server,
            route,
            outbound,
            MeshAttach {
                target_display: Arc::from(target_display.as_str()),
                kind: MeshAttachKind::Tcp,
            },
        )
        .await?;
        return Ok(());
    }

    // Resume attempt: re-attach to a parked VLESS-TCP upstream when the
    // client offered a Session ID that this user owns. The target sent
    // in the VLESS request is intentionally ignored on a hit — by spec
    // the parked target is authoritative.
    let user_id_for_resume = user.label_arc();
    if let Some(resume_id) = state.pending_resume_request.take()
        && let ResumeOutcome::Hit(Parked::Tcp(parked)) = server
            .orphan_registry
            .take_for_resume(resume_id, &user_id_for_resume)
            .await
    {
        // A park minted under Shadowsocks is served here unchanged — see
        // `super::super::tcp`'s twin of this comment and
        // `docs/SESSION-RESUMPTION.md` § Cross-protocol resume. The response
        // header emitted just below is what this carrier owes its own client;
        // the park has no say in it.
        if parked.protocol != ParkedProtocol::Vless {
            server
                .metrics
                .record_orphan_resume_cross_protocol(parked.protocol.label(), "vless");
        }
        debug!(
            user = user.label(),
            path = %route.path,
            target = %parked.target_display,
            parked_protocol = parked.protocol.label(),
            "vless tcp upstream resumed from orphan registry"
        );
        // Send the standard VLESS response header so the client moves
        // its parser past the handshake before receiving payload.
        outbound
            .data_tx
            .send((outbound.make_binary)(carrier_padding::frame_downlink_message(
                route.padding,
                Bytes::from_static(&[vless::VERSION, 0x00]),
            )))
            .await
            .map_err(|error| anyhow!("failed to queue vless response header on resume: {error}"))?;

        // Restore the per-session Ack-Prefix counter from the parked
        // entry BEFORE we look at it for the v1 control-frame emit —
        // the counter we want to report is the cumulative upstream
        // byte count across the previous incarnation's lifetime, not
        // a fresh `0`.
        state.upstream_bytes_acked = Arc::clone(&parked.upstream_bytes_acked);

        // Ack-Prefix Protocol v1 emit on resume hit (VLESS-WS path):
        // queue the 14-byte plaintext control frame as the very next
        // WS Binary message after the VLESS response header. The
        // client's `VlessTcpReader::consume_ack_prefix*` path will
        // intercept these 14 bytes after the header parse completes.
        // Gated on `state.ack_prefix_requested` so old clients (or
        // clients that did not opt in on this dial) never see the
        // frame and continue treating the next bytes as application
        // payload.
        if state.ack_prefix_requested {
            let payload = outline_wire::resume::build_v1_payload(
                state.upstream_bytes_acked.load(std::sync::atomic::Ordering::Relaxed),
            );
            let make_binary = outbound.make_binary;
            outbound
                .data_tx
                .send(make_binary(carrier_padding::frame_downlink_message(
                    route.padding,
                    Bytes::copy_from_slice(&payload),
                )))
                .await
                .map_err(|error| {
                    anyhow!("failed to queue vless ack-prefix control frame on resume: {error}")
                })?;
            debug!(
                user = user.label(),
                path = %route.path,
                up_acked = state
                    .upstream_bytes_acked
                    .load(std::sync::atomic::Ordering::Relaxed),
                "emitted ack-prefix control frame on vless resume hit",
            );
        }

        // v2 Symmetric Downlink Replay: emit the "ORDR" frame as the
        // next WS Binary message after the v1 "ORSM" frame. Replay
        // payload is `[client_acked_offset, total_sent)` from the
        // parked ring; absent ring or eviction-rolled-past surfaces
        // as REPLAY_TRUNCATED + replay_len = 0. The frame is sent
        // through the same `outbound.data_tx` mpsc so its FIFO
        // ordering with the v1 frame is preserved on the wire.
        if state.symmetric_replay_requested {
            use crate::server::resumption::downlink_ring::ReplayOutcome;
            use outline_wire::resume::downlink_replay;
            let (flags, payload, ring_diag, truncate_reason) = match parked.downlink_ring.as_ref() {
                None => (downlink_replay::FLAG_REPLAY_TRUNCATED, Vec::new(), None, "no_ring"),
                Some(ring) => {
                    let guard = ring.lock();
                    let diag = (guard.oldest_offset(), guard.total_sent());
                    let outcome = guard.replay_from(state.client_acked_offset_request);
                    drop(guard);
                    match outcome {
                        ReplayOutcome::Available(bytes) => {
                            (downlink_replay::FLAGS_NONE, bytes, Some(diag), "")
                        },
                        ReplayOutcome::Truncated => (
                            downlink_replay::FLAG_REPLAY_TRUNCATED,
                            Vec::new(),
                            Some(diag),
                            "evicted",
                        ),
                        ReplayOutcome::OffsetAhead => {
                            warn!(
                                user = user.label(),
                                path = %route.path,
                                client_offset = state.client_acked_offset_request,
                                "v2 client claims more downstream bytes than server emitted; \
                                 treating as truncated"
                            );
                            (
                                downlink_replay::FLAG_REPLAY_TRUNCATED,
                                Vec::new(),
                                Some(diag),
                                "client_ahead",
                            )
                        },
                    }
                },
            };
            let payload_len = payload.len() as u64;
            let truncated = (flags & downlink_replay::FLAG_REPLAY_TRUNCATED) != 0;
            server.metrics.record_orphan_downlink_replay_bytes("tcp", payload_len);
            if truncated {
                server
                    .metrics
                    .record_orphan_downlink_replay_truncated("tcp", truncate_reason);
            }
            let mut frame =
                Vec::with_capacity(downlink_replay::FRAME_HEADER_LEN_V1 + payload.len());
            frame.extend_from_slice(&downlink_replay::build_v1_header(flags, payload_len));
            frame.extend_from_slice(&payload);
            let make_binary = outbound.make_binary;
            outbound
                .data_tx
                .send(make_binary(carrier_padding::frame_downlink_message(
                    route.padding,
                    Bytes::copy_from_slice(&frame),
                )))
                .await
                .map_err(|error| {
                    anyhow!("failed to queue vless v2 downlink replay frame on resume: {error}")
                })?;
            let (ring_oldest, ring_total) = ring_diag.unwrap_or((0, 0));
            debug!(
                user = user.label(),
                path = %route.path,
                client_offset = state.client_acked_offset_request,
                replay_len = payload_len,
                truncated,
                ring_oldest_offset = ring_oldest,
                ring_total_sent = ring_total,
                "emitted v2 downlink replay frame on vless resume hit",
            );
        }

        // Restore the parked downlink ring onto the new state so
        // subsequent upstream→client bytes accumulate into the same
        // buffer; allocate a fresh empty one if the parked side was
        // None and v2 is engaged on this resume.
        if state.symmetric_replay_requested {
            state.downlink_ring = parked.downlink_ring.clone().or_else(|| {
                let cap = server.orphan_registry.downlink_buffer_bytes();
                if cap > 0 {
                    Some(Arc::new(parking_lot::Mutex::new(
                        crate::server::resumption::downlink_ring::DownlinkRing::new(cap),
                    )))
                } else {
                    None
                }
            });
        }
        let ring_for_task = state.downlink_ring.clone();
        let monitor_for_task = state.throttle_monitor.clone();
        let tx = outbound.data_tx.clone();
        let metrics = Arc::clone(&server.metrics);
        let user_id_for_relay = Arc::clone(&user_id_for_resume);
        let protocol = route.protocol;
        let padding = route.padding;
        let cancel = Arc::new(Notify::new());
        let cancel_for_task = Arc::clone(&cancel);
        let parked_reader = parked.upstream_reader;
        let make_binary = outbound.make_binary;
        let make_close = outbound.make_close;
        let reader_task = AbortOnDrop::new(tokio::spawn(async move {
            relay_vless_upstream_to_client(
                parked_reader,
                HarvestedUpstream::Tcp,
                tx,
                make_binary,
                make_close,
                metrics,
                protocol,
                user_id_for_relay,
                Some(cancel_for_task),
                ring_for_task,
                padding,
                monitor_for_task,
            )
            .await
        }));
        state.user_counters = Some(parked.user_counters);
        state.authenticated_user = Some(user);
        state.upstream = UpstreamSession::Tcp(TcpUpstream {
            writer: UpstreamWriter::Tcp(parked.upstream_writer),
            reader_task,
            cancel,
            target_display: parked.target_display,
            guard: Some(parked.upstream_guard),
        });

        // Forward any payload bytes that arrived in the same WS frame
        // as the VLESS request header.
        let leftover = state.header_buffer.split_off(request.consumed);
        state.header_buffer.clear();
        if !leftover.is_empty()
            && let UpstreamSession::Tcp(tcp) = &mut state.upstream
        {
            if let Some(counters) = &state.user_counters {
                counters
                    .tcp_in(AppProtocol::Vless, route.protocol)
                    .increment(leftover.len() as u64);
            }
            let leftover_len = leftover.len() as u64;
            tcp.writer
                .write_all(&leftover)
                .await
                .context("failed to write initial vless payload upstream after resume")?;
            // Same Ack-Prefix counter handoff as the regular relay
            // path — these bytes were just written to the upstream
            // socket and now belong to its kernel send buffer.
            state
                .upstream_bytes_acked
                .fetch_add(leftover_len, std::sync::atomic::Ordering::Relaxed);
        }
        return Ok(());
    }

    let connect_started = std::time::Instant::now();
    let stream = match connect_tcp_target(
        server.dns_cache.as_ref(),
        &target,
        user.fwmark(),
        server.prefer_ipv4_upstream,
        server.outbound_ipv6.as_deref(),
    )
    .await
    {
        Ok(stream) => {
            server.metrics.record_tcp_connect(
                user.label_arc(),
                route.protocol,
                AppProtocol::Vless,
                "success",
                connect_started.elapsed().as_secs_f64(),
            );
            stream
        },
        Err(error) => {
            server.metrics.record_tcp_connect(
                user.label_arc(),
                route.protocol,
                AppProtocol::Vless,
                "error",
                connect_started.elapsed().as_secs_f64(),
            );
            warn!(
                user = user.label(),
                protocol = ?route.protocol,
                path = %route.path,
                target = %target_display,
                error = %error,
                "vless upstream connect failed; sending try-again close to client"
            );
            return Err(VlessFrameError::UpstreamConnectFailed(
                anyhow::Error::msg(format!("{error:#}"))
                    .context(format!("failed to connect to {target_display}"))
                    .context("vless upstream tcp connect failed"),
            ));
        },
    };

    let (upstream_reader, writer) = stream.into_split();
    outbound
        .data_tx
        .send((outbound.make_binary)(carrier_padding::frame_downlink_message(
            route.padding,
            Bytes::from_static(&[vless::VERSION, 0x00]),
        )))
        .await
        .map_err(|error| anyhow!("failed to queue vless response header: {error}"))?;

    let tx = outbound.data_tx.clone();
    let metrics = Arc::clone(&server.metrics);
    let user_id = user.label_arc();
    let protocol = route.protocol;
    let padding = route.padding;
    // Cancel-notify is registered unconditionally so park-on-drop can
    // harvest the reader. When resumption is disabled the notify is
    // simply never fired and the relay loop runs in its single-arm
    // (legacy) mode.
    let cancel = Arc::new(Notify::new());
    let cancel_for_task = Arc::clone(&cancel);
    // v2 ring allocation at fresh-dial time. Parser already gated
    // `state.symmetric_replay_requested` on (a) v1 also requested
    // and (b) registry capacity > 0, so a `true` flag here is safe
    // to honour.
    if state.symmetric_replay_requested && state.downlink_ring.is_none() {
        let cap = server.orphan_registry.downlink_buffer_bytes();
        if cap > 0 {
            state.downlink_ring = Some(Arc::new(parking_lot::Mutex::new(
                crate::server::resumption::downlink_ring::DownlinkRing::new(cap),
            )));
        }
    }
    let ring_for_task = state.downlink_ring.clone();
    let monitor_for_task = state.throttle_monitor.clone();
    let reader_task = AbortOnDrop::new(tokio::spawn(async move {
        relay_vless_upstream_to_client(
            upstream_reader,
            HarvestedUpstream::Tcp,
            tx,
            outbound.make_binary,
            outbound.make_close,
            metrics,
            protocol,
            user_id,
            Some(cancel_for_task),
            ring_for_task,
            padding,
            monitor_for_task,
        )
        .await
    }));
    server.metrics.record_tcp_authenticated_session(
        user.label_arc(),
        route.protocol,
        AppProtocol::Vless,
    );
    let guard = server.metrics.open_tcp_upstream_connection(
        user.label_arc(),
        route.protocol,
        AppProtocol::Vless,
    );
    state.user_counters = Some(server.metrics.user_counters(&user.label_arc()));
    state.authenticated_user = Some(user);
    state.upstream = UpstreamSession::Tcp(TcpUpstream {
        writer: UpstreamWriter::Tcp(writer),
        reader_task,
        cancel,
        target_display: Arc::from(target_display.as_str()),
        guard: Some(guard),
    });

    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    if !leftover.is_empty()
        && let UpstreamSession::Tcp(tcp) = &mut state.upstream
    {
        if let Some(counters) = &state.user_counters {
            counters
                .tcp_in(AppProtocol::Vless, route.protocol)
                .increment(leftover.len() as u64);
        }
        let leftover_len = leftover.len() as u64;
        tcp.writer
            .write_all(&leftover)
            .await
            .context("failed to write initial vless payload upstream")?;
        // Mirror the same counter handoff as `forward_vless_data`
        // (and the SS-WS path) so initial-frame bytes are reflected
        // in `upstream_bytes_acked` before any park can occur.
        state
            .upstream_bytes_acked
            .fetch_add(leftover_len, std::sync::atomic::Ordering::Relaxed);
    }

    Ok(())
}

/// What the edge is relaying over a byte-stream mesh upstream.
///
/// Both kinds relay plaintext bytes and neither is ever parked here, so they
/// share [`attach_mesh_upstream`]; the enum names the two client-facing
/// decisions that do differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MeshAttachKind {
    /// A single-target VLESS-TCP session: the body is payload for one upstream
    /// socket on the home.
    Tcp,
    /// A VLESS-mux session: the body is the client's own mux frame stream,
    /// forwarded verbatim to the home, which runs the frame layer over the
    /// bundle of sub-connections it parked.
    Mux,
}

impl MeshAttachKind {
    /// Whether the home's acked upstream offset is re-emitted to the client as
    /// the Ack-Prefix v1 control frame.
    ///
    /// Only for `Tcp`. A mux session has no single uplink byte offset — its
    /// upstreams are many sockets behind a frame layer, and the home reports
    /// `0` — and a 14-byte control frame injected ahead of a mux frame stream
    /// would be parsed as a malformed frame. The direct mux path emits none
    /// either, on a fresh session or a resume, so a relayed mux looks exactly
    /// like a local one from the client's side.
    fn emits_ack_prefix(self) -> bool {
        matches!(self, MeshAttachKind::Tcp)
    }

    /// Whether this attach counts an authenticated TCP session.
    ///
    /// Only for `Tcp`, again to match the direct path: a mux session records no
    /// such sample there, so counting one here would make the series depend on
    /// whether a mux happened to be relayed.
    fn records_authenticated_session(self) -> bool {
        matches!(self, MeshAttachKind::Tcp)
    }
}

/// The two things [`attach_mesh_upstream`] needs beyond the session state: what
/// to call the upstream in logs, and which kind of body it carries.
pub(super) struct MeshAttach {
    /// Human-readable upstream label, for logging only. A relayed session is
    /// never parked on the edge, so this never becomes a park's target.
    pub(super) target_display: Arc<str>,
    pub(super) kind: MeshAttachKind,
}

/// Cluster edge: completes the v5 mesh hand-off for a VLESS session whose
/// upstream lives on the home — a single-target TCP socket or a whole mux
/// bundle — and wires the mesh stream in where a TCP socket would be.
///
/// Runs the second phase of the two-phase OPEN. The home acked phase 1 ("a
/// TCP-shaped park exists under this id") before the client carrier was
/// upgraded; only now, with the client authenticated against **this node's**
/// VLESS credentials, can the edge name the user — so the USER frame goes out
/// here, and the home answers the owner check by either splicing the park onto
/// the stream or resetting it.
///
/// The client's UUID is matched against this edge's own route, which is why the
/// home's UUID need not be the same one: the mesh carries VLESS *payload*, not
/// the VLESS handshake, so the two nodes authenticate independently. The
/// standard `[VERSION, 0x00]` response header is therefore emitted here too —
/// the home no longer speaks VLESS on this session at all.
///
/// The home's [`crate::server::cluster::mesh::UpstreamAckFrame`] is translated
/// straight into the Ack-Prefix v1 control frame the client already understands,
/// exactly as the SS edge does: the offset belongs to the client, which keeps
/// the replay buffer, so passing it on is what keeps the request body whole
/// across a node switch — for the commands that have such an offset, see
/// [`MeshAttachKind`].
///
/// Two commands ride this one function, because from the edge's side they are
/// the same session: a byte stream in each direction, with the client's crypto
/// terminated here and the upstream owned there. What differs is only what the
/// bytes *are* — payload for `Tcp`, the client's own mux frame stream for `Mux`
/// — which the edge never has to look at.
#[allow(clippy::too_many_arguments)]
pub(super) async fn attach_mesh_upstream<Msg>(
    state: &mut VlessRelayState,
    setup: MeshUpstreamSetup,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    outbound: VlessWsOutbound<'_, Msg>,
    attach: MeshAttach,
) -> Result<(), VlessFrameError>
where
    Msg: Send + 'static,
{
    let MeshAttach { target_display, kind } = attach;
    let user_id = user.label_arc();
    // A hand-off that fails here — the home refused the owner check, or the mesh
    // broke — is retryable, not a protocol fault: the client is authenticated,
    // so it gets a "try again" close and reconnects, and the next attempt finds
    // no park and is served locally. `Fatal` would instead run the
    // anti-fingerprinting inbound sink, which exists for unauthenticated probes.
    let MeshUpstreamHalves { writer, reader, upstream_acked } =
        setup.attach(&user_id).await.map_err(|error| {
            VlessFrameError::UpstreamConnectFailed(error.context("mesh relay hand-off failed"))
        })?;

    outbound
        .data_tx
        .send((outbound.make_binary)(carrier_padding::frame_downlink_message(
            route.padding,
            Bytes::from_static(&[vless::VERSION, 0x00]),
        )))
        .await
        .map_err(|error| {
            anyhow!("failed to queue vless response header for a relayed session: {error}")
        })?;

    // Ack-Prefix Protocol v1. Ordering is the same as the direct path's: ahead
    // of any relayed byte, on the same FIFO channel, so it lands right after the
    // response header and before whatever the spawned relay task produces.
    //
    // No v2 "ORDR" frame ever follows it: `edge_upstream` leaves
    // `symmetric_replay_requested` unset on a relayed session, because the
    // home's replay suffix arrives as undelimited plaintext the edge cannot
    // frame. The client consumes those bytes as ordinary stream continuation.
    if state.ack_prefix_requested && kind.emits_ack_prefix() {
        let payload = outline_wire::resume::build_v1_payload(upstream_acked);
        outbound
            .data_tx
            .send((outbound.make_binary)(carrier_padding::frame_downlink_message(
                route.padding,
                Bytes::copy_from_slice(&payload),
            )))
            .await
            .map_err(|error| {
                anyhow!(
                    "failed to queue vless ack-prefix control frame for a relayed session: {error}"
                )
            })?;
        debug!(
            user = user.label(),
            path = %route.path,
            up_acked = upstream_acked,
            "emitted ack-prefix control frame for a relayed vless session",
        );
    }

    let tx = outbound.data_tx.clone();
    let metrics = Arc::clone(&server.metrics);
    let user_id_for_relay = Arc::clone(&user_id);
    let protocol = route.protocol;
    let padding = route.padding;
    let monitor_for_task = state.throttle_monitor.clone();
    // Registered as on the direct path, though nothing here ever parks: the
    // notify is what lets teardown stop the reader cooperatively instead of
    // aborting it mid-write to the client.
    let cancel = Arc::new(Notify::new());
    let cancel_for_task = Arc::clone(&cancel);
    let make_binary = outbound.make_binary;
    let make_close = outbound.make_close;
    let reader_task = AbortOnDrop::new(tokio::spawn(async move {
        relay_vless_upstream_to_client(
            reader,
            harvest_mesh,
            tx,
            make_binary,
            make_close,
            metrics,
            protocol,
            user_id_for_relay,
            Some(cancel_for_task),
            // No v2 ring: the ring belongs to the node that owns the park, and
            // this session's park lives on the home, which captures into its own.
            None,
            padding,
            monitor_for_task,
        )
        .await
    }));
    if kind.records_authenticated_session() {
        server.metrics.record_tcp_authenticated_session(
            Arc::clone(&user_id),
            route.protocol,
            AppProtocol::Vless,
        );
    }
    state.user_counters = Some(server.metrics.user_counters(&user_id));
    state.authenticated_user = Some(user);
    state.upstream = UpstreamSession::Tcp(TcpUpstream {
        writer,
        reader_task,
        cancel,
        target_display,
        // No upstream-connection gauge: it counts real upstream sockets, and
        // this node holds none. Leaving it `None` also keeps the park path
        // refusing this session for a third, independent reason.
        guard: None,
    });

    // Forward any payload bytes that arrived in the same WS frame as the VLESS
    // request header.
    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    if !leftover.is_empty()
        && let UpstreamSession::Tcp(tcp) = &mut state.upstream
    {
        if let Some(counters) = &state.user_counters {
            counters
                .tcp_in(AppProtocol::Vless, route.protocol)
                .increment(leftover.len() as u64);
        }
        let leftover_len = leftover.len() as u64;
        // A mesh write that fails — most often a stall past the health budget —
        // is retryable for the same reason the hand-off above is.
        tcp.writer.write_all(&leftover).await.map_err(|error| {
            VlessFrameError::UpstreamConnectFailed(
                anyhow::Error::new(error)
                    .context("failed to write initial vless payload over the mesh"),
            )
        })?;
        state
            .upstream_bytes_acked
            .fetch_add(leftover_len, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// Harvest mapping for a relayed upstream: there is nothing to hand on, because
/// the socket lives on the home. Mirrors `tcp::harvest_tcp` on the SS side.
fn harvest_mesh(_reader: MeshUpstream) -> HarvestedUpstream {
    HarvestedUpstream::Mesh
}

#[allow(clippy::too_many_arguments)]
async fn relay_vless_upstream_to_client<R, Msg>(
    mut upstream_reader: R,
    // How the harvested reader is reported when the caller cancels. A direct
    // upstream hands its `OwnedReadHalf` on for parking; a mesh one has nothing
    // to hand on. A function pointer rather than a `From` impl so the two
    // shapes stay explicit at each spawn site.
    harvest: fn(R) -> HarvestedUpstream,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user_id: Arc<str>,
    cancel: Option<Arc<Notify>>,
    // v2 Symmetric Downlink Replay capture point — pushed BEFORE the
    // WS Binary send so `total_sent` always reflects what the server
    // committed to send. `None` when v2 is not engaged on this session.
    downlink_ring: Option<
        Arc<parking_lot::Mutex<crate::server::resumption::downlink_ring::DownlinkRing>>,
    >,
    // Carrier-padding scheme for this path; disabled → plain wire.
    padding: PaddingScheme,
    // Per-carrier downstream-throttle monitor; `Some` only on a padded path
    // with detection on. Fed inbound (from-internet) bytes + send backlog.
    monitor: Option<Arc<super::super::throughput_monitor::ThroughputMonitor>>,
) -> VlessRelayTaskOutput
where
    R: UpstreamRead,
    Msg: Send + 'static,
{
    let user_counters = metrics.user_counters(&user_id);
    let target_to_client = user_counters.tcp_out(AppProtocol::Vless, protocol);
    // Reused per-connection downlink buffer: read straight into it, then hand
    // the filled region off with a zero-copy `split_to().freeze()`. Empty (and
    // unallocated) until the first ready read, so a parked/idle session holds
    // nothing; it drops when this relay call returns on park or close.
    let mut downlink_buf = BytesMut::new();
    loop {
        // Cancel arm: when no notify is registered, substitute a never-
        // resolving future so the select degenerates to a single-arm
        // read loop matching the legacy behaviour.
        let cancelled = async {
            match cancel.as_deref() {
                Some(notify) => notify.notified().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            _ = cancelled => {
                // Do NOT push a Close frame here: the caller is parking
                // the upstream so a subsequent resume can reattach a
                // new client stream. Sending Close would race the
                // reconnect.
                return Ok(VlessRelayOutcome::Cancelled(harvest(upstream_reader)));
            }
            ready = upstream_reader.readable() => {
                ready.context("failed to await vless upstream")?;
                // Reserve into the reused buffer only once data is ready.
                downlink_buf.reserve(GREEDY_DRAIN_TARGET);
                let read = match upstream_reader.try_read_buf(&mut downlink_buf) {
                    Ok(read) => read,
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error).context("failed to read from vless upstream"),
                };
                if read == 0 {
                    break;
                }
                // Greedy-drain: see `relay::relay_upstream_to_client`.
                // VLESS-WS has no inner AEAD chunking, so the only
                // amortisation knob is mpsc push + ws-writer send +
                // TLS-record header per emitted frame. Pulling more
                // already-buffered upstream bytes into a single binary
                // frame collapses ~14k frames/sec at 200 Mbit into
                // ~1.5k while never yielding the runtime.
                while downlink_buf.len() < GREEDY_DRAIN_TARGET {
                    match upstream_reader.try_read_buf(&mut downlink_buf) {
                        Ok(0) => break, // EOF: send what we have
                        Ok(_) => {},    // got more, keep pulling
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error).context("failed to drain vless upstream"),
                    }
                }
                let total = downlink_buf.len();
                target_to_client.increment(total as u64);
                // Throttle detection: count bytes pulled from the internet
                // (inbound) for this carrier.
                if let Some(m) = monitor.as_ref() {
                    m.add_inbound(total as u64);
                }
                // v2 capture: push plaintext into the ring BEFORE the
                // WS Binary send so `total_sent` always reflects what
                // the server has committed to send.
                if let Some(ring) = downlink_ring.as_ref() {
                    ring.lock().push(&downlink_buf[..total]);
                }
                let used = tx.max_capacity().saturating_sub(tx.capacity());
                metrics.observe_ws_data_channel_fill(
                    crate::metrics::Transport::Tcp,
                    crate::metrics::AppProtocol::Vless,
                    used,
                );
                // Throttle detection: note a send backlog (data channel past
                // its half-full high-water mark) so a low out-rate is read as
                // genuine downstream backpressure, not just an idle client.
                if let Some(m) = monitor.as_ref()
                    && used.saturating_mul(2) >= tx.max_capacity()
                {
                    m.note_backlog();
                }
                // Zero-copy hand-off: the frozen slice shares the buffer's
                // allocation; `frame_downlink_message` forwards it unchanged on
                // the unpadded path. `split_to` keeps any spare tail capacity in
                // `downlink_buf` for the next read.
                let payload = downlink_buf.split_to(total).freeze();
                let frame = carrier_padding::frame_downlink_message(padding, payload);
                tx.send(make_binary(frame))
                    .await
                    .map_err(|error| anyhow!("failed to queue vless websocket frame: {error}"))?;
            }
        }
    }
    let _ = tx.send(make_close()).await;
    Ok(VlessRelayOutcome::Closed)
}
