use std::{sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use outline_wire::padding::PaddingDecoder;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::server::cluster::mesh::MeshShape;
use crate::server::h3::vendored::{H3Stream, H3Transport, H3WebSocketStream};
use crate::{
    metrics::{AppProtocol, Transport},
    protocol::vless::{self, VlessCommand, VlessUser, mask_uuid},
};

use super::super::{
    constants::{
        WS_CTRL_CHANNEL_CAPACITY, WS_PONG_DEADLINE_MULTIPLIER, WS_TCP_KEEPALIVE_PING_INTERVAL_SECS,
    },
    resumption::{Parked, ResumeOutcome, SessionId},
};
use super::carrier_padding;
use super::resume_headers::ResumeContext;
use super::sink;
use super::throughput_monitor;
use super::upstream_source::UpstreamSource;
use super::vless_mux::{self, MuxAccounting, MuxRouteCtx, MuxServerCtx, MuxState};
use super::vless_udp::{self, forward_vless_udp_client_frames};
use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;
use crate::server::abort::AbortOnDrop;

mod ctx;
mod tcp;
mod udp;

pub(in crate::server::transport) use ctx::{
    MuxUpstream, UdpUpstream, UpstreamSession, VlessFrameError, VlessRelayOutcome, VlessRelayState,
    VlessWsOutbound,
};
pub(in crate::server) use ctx::{VlessWsRouteCtx, VlessWsServerCtx};

use ctx::MAX_VLESS_HEADER_BUFFER;
use tcp::{
    MeshAttach, MeshAttachKind, attach_mesh_upstream, establish_vless_tcp_upstream,
    shutdown_unparked_tcp, try_park_vless_tcp,
};
use udp::try_park_vless_udp_single;

/// Serves one VLESS-over-WS/XHTTP session: authenticate the client, take an
/// upstream, and pump both directions until either end goes away.
///
/// `upstream` decides where that upstream comes from. [`UpstreamSource::Direct`]
/// is a node serving the session itself: it resumes a local park or connects out
/// to the target. [`UpstreamSource::Mesh`] is a cluster **edge** — the socket
/// lives on the home, so this node terminates the client's VLESS layer, attests
/// the user over the mesh and exchanges plaintext with the home instead of
/// dialling. A mesh session is never parked here (see [`try_park_vless_on_drop`]
/// and the guards in [`try_park_vless_tcp`]).
///
/// VLESS multiplexes TCP, UDP and mux onto one carrier, so which command a
/// session turns out to be is not known when the relay is opened. The home's ack
/// names the shape of the park it holds, and only a command that needs *that*
/// shape keeps the relay — a byte-stream park for `Tcp`, a single-target
/// VLESS-UDP one for `Udp`, a whole mux bundle for `Mux`. Any other pairing
/// releases the relay and is served locally ([`keep_mesh_upstream_for`]).
pub(in crate::server::transport) async fn run_vless_relay<T: WsSocket>(
    socket: T,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    resume: ResumeContext,
    upstream: UpstreamSource,
) -> Result<()> {
    let (mut reader, writer) = socket.split_io();
    let (outbound_data_tx, outbound_data_rx) =
        mpsc::channel::<T::Msg>(server.ws_data_channel_capacity);
    let (outbound_ctrl_tx, outbound_ctrl_rx) = mpsc::channel::<T::Msg>(WS_CTRL_CHANNEL_CAPACITY);
    // Per-carrier downstream-throttle monitor, built from the route: `Some` only
    // on a padded path with detection enabled, else `None` keeps the wire
    // identical.
    let throttle_monitor = carrier_padding::throttle_params_for_path(&route.path)
        .map(throughput_monitor::ThroughputMonitor::new);
    let writer_task = tokio::spawn(ws_writer::run_ws_writer::<T>(
        writer,
        outbound_ctrl_rx,
        outbound_data_rx,
        server.metrics.clone(),
        Transport::Tcp,
        route.protocol,
        AppProtocol::Vless,
        // Idle cover traffic on the downlink when this path opts into padding.
        // Covers VLESS-over-WS and VLESS-over-XHTTP alike (both ride this
        // writer); a cover frame is a `Binary` message the client's decoder
        // drops transparently.
        carrier_padding::cover_for_path(&route.path),
        throttle_monitor.clone(),
    ));
    // Detection tick. Bounded: aborted when this handle drops at carrier
    // teardown, so it never outlives the carrier.
    let _throttle_tick = throttle_monitor
        .clone()
        .map(|m| AbortOnDrop::new(tokio::spawn(throughput_monitor::run_throttle_tick(m))));

    let ping_interval = Duration::from_secs(WS_TCP_KEEPALIVE_PING_INTERVAL_SECS);
    let pong_deadline = ping_interval * WS_PONG_DEADLINE_MULTIPLIER;
    let mut keepalive = tokio::time::interval(ping_interval);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;

    let mut state = VlessRelayState::new(resume, throttle_monitor, upstream);
    let mut client_closed = false;
    // A carrier that *died* rather than closed, held until after the park
    // below. Returning on the spot would skip `try_park_vless_on_drop` — and a
    // dirty death is exactly the case whose client comes back with a resume
    // request. Mirrors the SS-WS and SS-UDP paths.
    let mut carrier_error: Option<anyhow::Error> = None;
    // Carrier-padding decoder for the uplink, allocated only when this path
    // pads. Held across the loop because a padding frame may span WS/h2/h3 DATA
    // frame boundaries. Covers VLESS-TCP and VLESS-UDP uplink alike — the
    // client frames both legs on a padded path (config-synchronised gate).
    let mut padding_decoder = route.padding.is_enabled().then(PaddingDecoder::new);
    // Last instant any inbound WS frame was observed; reset on every recv.
    // The keepalive tick checks this against `pong_deadline` and tears the
    // session down if the peer has gone silent (mobile in tunnel, NAT
    // rebind, ISP black-hole) — without it the only timeout is the
    // underlying TCP/QUIC keepalive which may take minutes or never fire,
    // leaving UDP-upstream sockets and 64 KiB reader buffers pinned.
    let mut last_inbound = std::time::Instant::now();

    loop {
        tokio::select! {
            biased;
            result = T::recv(&mut reader) => {
                let msg = match result {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(error) => {
                        carrier_error = Some(error);
                        break;
                    },
                };
                last_inbound = std::time::Instant::now();
                match T::classify(msg) {
                    WsFrame::Binary(data) => {
                        // Strip carrier padding before VLESS parsing/relaying
                        // when this path pads. A cover frame (real_len = 0)
                        // decodes to nothing and is skipped; a padding frame may
                        // span DATA frames, so the decoder state lives across
                        // the loop.
                        let data = match padding_decoder.as_mut() {
                            Some(decoder) => {
                                let mut out = Vec::with_capacity(data.len());
                                decoder.push(&data, &mut out);
                                if out.is_empty() {
                                    continue;
                                }
                                Bytes::from(out)
                            },
                            None => data,
                        };
                        if let Err(frame_err) = handle_vless_binary_frame(
                            &mut state,
                            data,
                            server,
                            route,
                            VlessWsOutbound {
                                data_tx: &outbound_data_tx,
                                make_binary: T::binary_msg,
                                make_close: T::close_msg,
                            },
                        )
                        .await
                        {
                            // Mirror the SS path: send a graceful WS close
                            // frame before tearing the channels down.  Without
                            // this the writer task exits silently and the peer
                            // sees an abrupt TCP/QUIC RST instead of an RFC
                            // 6455 close — a sharp signature for active probes
                            // that distinguishes VLESS from a benign WS peer.
                            //
                            // For Fatal (parser/auth) failures we additionally
                            // run the inbound side through `sink::sink_ws`
                            // before the close: the VLESS parser bails on the
                            // 18th byte while the SS-AEAD path stalls until
                            // the handshake timeout, so an immediate close
                            // *also* leaks a timing fingerprint. Sinking
                            // until the same handshake timeout (or a 64 KiB
                            // cap) collapses that distinguisher.
                            // UpstreamConnectFailed is a post-handshake
                            // failure on an authenticated session — there is
                            // no probe to mask, so the client gets an
                            // immediate Try-Again close.
                            let (close_msg, sinked) = match &frame_err {
                                VlessFrameError::UpstreamConnectFailed(_) => {
                                    (T::close_try_again_msg(), false)
                                },
                                VlessFrameError::Fatal(_) => {
                                    sink::sink_ws::<T>(&mut reader).await;
                                    (T::close_msg(), true)
                                },
                            };
                            let _ = outbound_ctrl_tx.send(close_msg).await;
                            drop(outbound_ctrl_tx);
                            drop(outbound_data_tx);
                            let _ = writer_task.await;
                            let mut error = frame_err.into_inner();
                            if sinked {
                                error = error.context(sink::HandshakeRejectedMarker);
                            }
                            return Err(error);
                        }
                    },
                    WsFrame::Close => {
                        debug!("client closed vless websocket");
                        client_closed = true;
                        break;
                    },
                    WsFrame::Ping(payload) => {
                        outbound_ctrl_tx
                            .send(T::pong_msg(payload))
                            .await
                            .map_err(|_| anyhow!("failed to queue websocket pong"))?;
                    },
                    WsFrame::Pong => {},
                    WsFrame::Text => return Err(anyhow!("text websocket frames are not supported")),
                }
            },
            // Disabled on the H3 carrier (see `WsSocket::is_h3`): a server
            // Ping would risk a connection-level `H3_INTERNAL_ERROR`, and the
            // pong-deadline reaping would false-fire because the client's
            // keepalive Pings are swallowed by the split reader. QUIC
            // keep-alive detects a dead peer; the writer's flush delivers the
            // reactive Pong.
            _ = keepalive.tick(), if !T::is_h3() => {
                if last_inbound.elapsed() > pong_deadline {
                    debug!(
                        elapsed_secs = last_inbound.elapsed().as_secs(),
                        "vless websocket pong deadline exceeded; closing session"
                    );
                    server
                        .metrics
                        .record_pong_deadline_disconnect(Transport::Tcp, AppProtocol::Vless);
                    break;
                }
                let _ = outbound_ctrl_tx.send(T::ping_msg()).await;
            }
        }
    }

    // Try parking the upstream into the orphan registry. Returns `true` if it
    // was moved there; in that case the regular shutdown branch below is
    // skipped. A relayed session never parks here — the upstream lives on the
    // home — and falls through to the teardown that FINs the mesh half.
    let parked = try_park_vless_on_drop(&mut state, server, route).await;

    // Reader tasks inside `Tcp(_)`/`Udp(_)` are `AbortOnDrop`, so dropping
    // `state.upstream` (either via the `mem::replace` below on the
    // unparked path, or at function exit on the parked path where it's
    // already `None`) cancels them. We don't await them: for TCP/MUX the
    // reader self-exits in microseconds anyway after the upstream
    // shutdown above, and for UDP awaiting would hang forever on
    // `socket.recv`.
    if !parked {
        match std::mem::replace(&mut state.upstream, UpstreamSession::None) {
            UpstreamSession::Tcp(tcp) => {
                shutdown_unparked_tcp(tcp.writer, tcp.guard).await;
            },
            UpstreamSession::Mux(mut mux) => {
                mux.mux.shutdown().await;
            },
            // A relayed UDP session ends its uplink half with a QUIC FIN, which
            // is what tells the home the carrier ended cleanly and its socket is
            // worth re-parking; a reset would read as a broken relay. A direct
            // socket has nothing to end and this is a no-op for it.
            UpstreamSession::Udp(mut udp) => udp.sink.shutdown().await,
            UpstreamSession::None => {},
        }
    }

    let _ = client_closed;
    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    let _ = writer_task.await;
    match carrier_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Attempts to move the live VLESS upstream into the orphan registry.
/// Returns `true` iff the upstream was parked; on `false` the caller
/// performs the legacy shutdown.
///
/// Two upstream shapes are eligible:
/// - **Single-target TCP** (`UpstreamSession::Tcp`): the same hand-off
///   as the SS-WS path, parked under [`Parked::Tcp`].
/// - **VLESS mux** (`UpstreamSession::Mux`): every sub-connection is
///   harvested and packed into a single [`Parked::VlessMux`] entry —
///   atomic park, by-design no partial-resume.
///
/// UDP single-target sessions and unauthenticated sessions still fall
/// through to the legacy shutdown path.
async fn try_park_vless_on_drop(
    state: &mut VlessRelayState,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
) -> bool {
    if !server.orphan_registry.enabled() {
        return false;
    }
    let Some(session_id) = state.issued_session_id else {
        return false;
    };
    // Reserve the id for the whole harvest+park below (each variant awaits its
    // reader harvest), so a racing client redial waits for the park instead of
    // missing it. The guard clears the reservation on every return path.
    let _reservation = server.orphan_registry.reserve_park(session_id);
    match state.upstream {
        UpstreamSession::Tcp(_) => try_park_vless_tcp(state, server, route, session_id).await,
        UpstreamSession::Udp(_) => {
            try_park_vless_udp_single(state, server, route, session_id).await
        },
        UpstreamSession::Mux(_) => try_park_vless_mux(state, server, route, session_id).await,
        UpstreamSession::None => false,
    }
}

/// Atomic VLESS-mux park. Replaces `state.upstream` with `None`,
/// harvests every sub-connection's reader half (for TCP) or socket
/// reference (for UDP), and inserts the whole bundle as a single
/// [`Parked::VlessMux`] entry. Empty muxes are not parked — there is
/// no useful state left to reattach.
async fn try_park_vless_mux(
    state: &mut VlessRelayState,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    session_id: SessionId,
) -> bool {
    let mux = match std::mem::replace(&mut state.upstream, UpstreamSession::None) {
        UpstreamSession::Mux(mux) => mux.mux,
        other => {
            // Should not happen given the caller's match, but keep the
            // cleanup honest by restoring whatever we found.
            state.upstream = other;
            return false;
        },
    };
    if !mux.is_parkable() {
        // No live sub-conns — restore as None (already done) and let
        // the caller's legacy path handle the rest.
        return false;
    }
    let Some(user) = state.authenticated_user.take() else {
        // No authenticated user means we never finished the handshake;
        // mux state is bogus.
        return false;
    };
    let owner = user.label_arc();
    let parked = mux.harvest_into_parked(Arc::clone(&owner)).await;
    if parked.sub_conns.is_empty() {
        // All sub-conns failed to harvest (cancel races / reader
        // panics). Nothing worth the registry slot.
        state.authenticated_user = Some(user);
        return false;
    }
    debug!(
        user = %owner,
        path = %route.path,
        sub_conns = parked.sub_conns.len(),
        "parking vless mux upstream into orphan registry",
    );
    server.orphan_registry.park(session_id, Parked::VlessMux(parked));
    // Mirror the TCP path's restoration so the caller sees a still-
    // populated `authenticated_user` for any post-park bookkeeping
    // (e.g. session-finish guards). The cloned `Arc<str>` is cheap.
    state.authenticated_user = Some(user);
    true
}

async fn handle_vless_binary_frame<Msg>(
    state: &mut VlessRelayState,
    data: Bytes,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    outbound: VlessWsOutbound<'_, Msg>,
) -> Result<(), VlessFrameError>
where
    Msg: Send + 'static,
{
    use anyhow::Context;

    server.metrics.record_websocket_binary_frame(
        Transport::Tcp,
        route.protocol,
        AppProtocol::Vless,
        "up",
        data.len(),
    );

    let counters = state.user_counters.as_deref();
    match &mut state.upstream {
        UpstreamSession::Tcp(tcp) => {
            if let Some(counters) = counters {
                counters
                    .tcp_in(AppProtocol::Vless, route.protocol)
                    .increment(data.len() as u64);
            }
            let payload_len = data.len() as u64;
            // A relayed upstream that fails — most often a mesh write stalling
            // past the health budget — is retryable, not a protocol fault: the
            // client is already authenticated, so it gets a "try again" close
            // and reconnects, while the home's park TTL-expires. Routing it
            // through `Fatal` instead would first run the anti-fingerprinting
            // inbound sink, which exists for *unauthenticated* probes and would
            // hold a wedged carrier open for its whole duration. Mirrors the SS
            // path's `forward_plaintext_to_writer`.
            let is_mesh = tcp.writer.is_mesh();
            tcp.writer
                .write_all(&data)
                .await
                .context("failed to write vless websocket data upstream")
                .map_err(|error| {
                    if is_mesh {
                        VlessFrameError::UpstreamConnectFailed(error)
                    } else {
                        VlessFrameError::Fatal(error)
                    }
                })?;
            // Bump the per-session upstream-acked counter only on a
            // successful `write_all` — same handoff semantics as the
            // SS-WS path's `forward_plaintext_to_writer`. Survives
            // park/resume because the `Arc` moves into `ParkedTcp` on
            // park and back into the relay state on the next resume
            // hit.
            state
                .upstream_bytes_acked
                .fetch_add(payload_len, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        },
        UpstreamSession::Udp(udp) => {
            // A relayed datagram sink that fails is retryable, not a protocol
            // fault, for the same reason the TCP arm above says so: the client
            // is already authenticated, so it gets a "try again" close instead
            // of the anti-fingerprinting sink meant for unauthenticated probes.
            let is_mesh = udp.sink.is_mesh();
            forward_vless_udp_client_frames(
                &mut udp.client_buffer,
                &data,
                &mut udp.sink,
                counters,
                route.protocol,
                &route.path,
            )
            .await
            .map_err(|error| {
                if is_mesh {
                    VlessFrameError::UpstreamConnectFailed(error)
                } else {
                    VlessFrameError::Fatal(error)
                }
            })?;
            return Ok(());
        },
        UpstreamSession::Mux(upstream) => {
            // Contexts were snapshotted when the mux upstream was established;
            // the frame path borrows them instead of rebuilding a throwaway
            // pair of `Arc` clones per data frame.
            vless_mux::handle_client_bytes(
                &mut upstream.mux,
                &data,
                &upstream.server,
                &upstream.route,
                outbound.data_tx,
                outbound.make_binary,
            )
            .await?;
            return Ok(());
        },
        UpstreamSession::None => {},
    }

    state.header_buffer.extend_from_slice(&data);

    let request = match vless::parse_request(&state.header_buffer) {
        Ok(Some(request)) => request,
        Ok(None) => {
            if state.header_buffer.len() > MAX_VLESS_HEADER_BUFFER {
                warn!(path = %route.path, buffered = state.header_buffer.len(), "vless parse error: request header too large");
                return Err(VlessFrameError::Fatal(anyhow!("vless request header too large")));
            }
            return Ok(());
        },
        Err(vless::VlessError::UnsupportedCommand(command)) => {
            warn!(path = %route.path, command, "unsupported vless command");
            return Err(VlessFrameError::Fatal(anyhow!("unsupported vless command {command:#x}")));
        },
        Err(error) => {
            warn!(path = %route.path, error = %error, "vless parse error");
            return Err(VlessFrameError::Fatal(anyhow!(error)));
        },
    };

    // Relabel by the client's source IP: downstream establishers read the
    // (now effective) accounting label off the instance, so no further
    // plumbing is needed. Accounting only — auth already matched the UUID.
    let user = match vless::find_user(route.users.as_ref(), &request.user_id)
        .cloned()
        .map(|u| u.with_effective_label(route.peer))
    {
        Some(user) => {
            info!(
                user = user.label(),
                path = %route.path,
                command = ?request.command,
                "accepted vless user"
            );
            user
        },
        None => {
            let masked = mask_uuid(&request.user_id);
            warn!(
                user = %masked,
                path = %route.path,
                candidates = ?route.candidate_users,
                "rejected vless user"
            );
            return Err(VlessFrameError::Fatal(anyhow!("unknown vless user {masked}")));
        },
    };

    match request.command {
        VlessCommand::Tcp => {
            keep_mesh_upstream_for(state, MeshShape::Stream, "tcp");
            establish_vless_tcp_upstream(state, request, user, server, route, outbound).await
        },
        VlessCommand::Udp => {
            keep_mesh_upstream_for(state, MeshShape::VlessUdpSingle, "udp");
            vless_udp::establish_vless_udp_upstream(state, request, user, server, route, outbound)
                .await
        },
        VlessCommand::Mux => {
            keep_mesh_upstream_for(state, MeshShape::VlessMux, "mux");
            establish_vless_mux_upstream(state, request, user, server, route, outbound).await
        },
    }
}

/// Keeps the mesh relay for a command whose upstream shape is the one the home
/// acked, and releases it otherwise.
///
/// This is the whole of the edge's half of the shape hand-off. The home named
/// the shape of the park it holds in its setup ack — the earliest moment either
/// node can know it, since the OPEN precedes the client's first frame (see
/// `cluster::mesh::frame`) — and the command just parsed names the shape this
/// session needs. When they agree the relay goes on to attest the user; when
/// they do not, the edge serves the session locally from here.
fn keep_mesh_upstream_for(state: &mut VlessRelayState, want: MeshShape, command: &'static str) {
    if state
        .mesh_upstream
        .as_ref()
        .is_some_and(|setup| setup.shape() != want)
    {
        release_mesh_upstream(state, command);
    }
}

/// Releases a mesh relay this session turned out not to be able to use, and
/// serves the session locally instead.
///
/// A cluster edge opens the relay before it can read the client's first frame,
/// so it does not yet know which VLESS command is coming — and the home's ack
/// therefore names the shape of the park it is holding. A command that needs
/// some other shape cannot use this relay: a `Tcp` command on a UDP-shaped park,
/// a `Mux` one on a byte-stream park, or any other pairing a client produces by
/// reusing one id across two session kinds, which VLESS lets it do. Those are
/// served from this node, which dials its own upstreams for them — including,
/// for a fresh `Mux`, its own sub-connections.
///
/// The timing is the point. This runs strictly **before** the USER frame, and
/// the USER frame is what makes the home consume its park — so the home keeps
/// whatever it was holding, and a later carrier can still resume it. That is the
/// second of two independent barriers: the home's own probes
/// (`OrphanRegistry::probe_park`, answering with a [`ParkProbe`]) refuse a
/// committed park of the wrong shape before `take_for_resume` touches it, and
/// this closes the reservation window those cannot see into.
///
/// [`ParkProbe`]: crate::server::resumption::ParkProbe
fn release_mesh_upstream(state: &mut VlessRelayState, command: &'static str) {
    if let Some(setup) = state.mesh_upstream.take() {
        setup.refuse();
        debug!(
            command,
            "vless command needs an upstream the mesh relay cannot carry; serving it locally"
        );
    }
}

async fn establish_vless_mux_upstream<Msg>(
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
    // Cluster edge: the whole bundle lives on the home, which is still waiting
    // to be told *who* this session belongs to. From here on this node is a pure
    // carrier — it forwards the client's mux frame stream verbatim and never
    // parses a mux frame, so the same byte-stream attach the TCP command uses
    // serves a mux session unchanged. Neither the local registry nor an outbound
    // dial is consulted: the home owns every sub-connection, and it opens new
    // ones for `New` frames too.
    if let Some(setup) = state.mesh_upstream.take() {
        return attach_mesh_upstream(
            state,
            setup,
            request,
            user,
            server,
            route,
            outbound,
            MeshAttach {
                target_display: Arc::from("vless-mux"),
                kind: MeshAttachKind::Mux,
            },
        )
        .await;
    }

    // Resume attempt: if the client offered a Session ID and the
    // registry has a parked VLESS-mux entry for this user, re-attach
    // every sub-connection atomically. The mux's request frame
    // arrives over the WS frame stream, so any leftover bytes after
    // the VLESS handshake are routed into the resumed mux just like
    // a fresh one.
    let user_id_for_resume = user.label_arc();
    if let Some(resume_id) = state.pending_resume_request.take()
        && let ResumeOutcome::Hit(parked_kind) = server
            .orphan_registry
            .take_for_resume(resume_id, &user_id_for_resume)
            .await
    {
        match parked_kind {
            Parked::VlessMux(parked) => {
                let sub_count = parked.sub_conns.len();
                info!(
                    user = user.label(),
                    path = %route.path,
                    sub_conns = sub_count,
                    "vless mux session resumed from orphan registry",
                );
                outbound
                    .data_tx
                    .send((outbound.make_binary)(Bytes::from_static(&[vless::VERSION, 0x00])))
                    .await
                    .map_err(|error| {
                        anyhow!("failed to queue vless mux response header on resume: {error}")
                    })?;

                let mux = vless_mux::attach_parked(
                    parked,
                    outbound.data_tx.clone(),
                    outbound.make_binary,
                    &server.metrics,
                    route.protocol,
                    // This node terminates the client session, so it counts.
                    MuxAccounting::Local,
                );
                state.user_counters = Some(server.metrics.user_counters(&user.label_arc()));
                state.authenticated_user = Some(user);
                state.upstream = UpstreamSession::Mux(mux_upstream(mux, server, route));

                // Forward any post-handshake bytes carried by the
                // current frame into the freshly-attached mux.
                let leftover = state.header_buffer.split_off(request.consumed);
                state.header_buffer.clear();
                if !leftover.is_empty()
                    && let UpstreamSession::Mux(upstream) = &mut state.upstream
                {
                    vless_mux::handle_client_bytes(
                        &mut upstream.mux,
                        &leftover,
                        &upstream.server,
                        &upstream.route,
                        outbound.data_tx,
                        outbound.make_binary,
                    )
                    .await?;
                }
                return Ok(());
            },
            other => {
                warn!(
                    user = user.label(),
                    path = %route.path,
                    parked_kind = other.kind(),
                    "rejecting vless mux resume: parked entry is not a mux"
                );
                return Err(VlessFrameError::Fatal(anyhow!(
                    "cross-shape resume rejected: parked session kind is {}, not mux",
                    other.kind(),
                )));
            },
        }
    }

    info!(user = user.label(), path = %route.path, "vless mux session (xudp)");

    outbound
        .data_tx
        .send((outbound.make_binary)(Bytes::from_static(&[vless::VERSION, 0x00])))
        .await
        .map_err(|error| anyhow!("failed to queue vless mux response header: {error}"))?;

    let user_counters = server.metrics.user_counters(&user.label_arc());
    let mux = MuxState::new(user.clone(), Arc::clone(&user_counters), MuxAccounting::Local);
    state.user_counters = Some(user_counters);
    state.authenticated_user = Some(user);

    let mut upstream = mux_upstream(mux, server, route);

    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    if !leftover.is_empty() {
        vless_mux::handle_client_bytes(
            &mut upstream.mux,
            &leftover,
            &upstream.server,
            &upstream.route,
            outbound.data_tx,
            outbound.make_binary,
        )
        .await?;
    }

    state.upstream = UpstreamSession::Mux(upstream);
    Ok(())
}

/// Snapshots the session's server / route context alongside a freshly
/// established (or resumed) mux, so the per-frame path can borrow them instead
/// of rebuilding both structs — and their `Arc` clones — on every data frame.
fn mux_upstream(mux: MuxState, server: &VlessWsServerCtx, route: &VlessWsRouteCtx) -> MuxUpstream {
    MuxUpstream {
        mux,
        server: MuxServerCtx {
            dns_cache: Arc::clone(&server.dns_cache),
            prefer_ipv4_upstream: server.prefer_ipv4_upstream,
            outbound_ipv6: server.outbound_ipv6.clone(),
            metrics: Arc::clone(&server.metrics),
        },
        route: MuxRouteCtx {
            protocol: route.protocol,
            path: Arc::clone(&route.path),
        },
    }
}

pub(super) async fn handle_vless_connection(
    socket: WebSocket,
    server: Arc<VlessWsServerCtx>,
    route: VlessWsRouteCtx,
    resume: ResumeContext,
    upstream: UpstreamSource,
) -> Result<()> {
    // Client-terminating carrier either way, so local throttle detection is the
    // right one — including for a relayed session, where this node still owns
    // the last mile to the client.
    run_vless_relay::<AxumWs>(AxumWs(socket), &server, &route, resume, upstream).await
}

pub(in crate::server) async fn handle_vless_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<VlessWsServerCtx>,
    route: VlessWsRouteCtx,
    resume: ResumeContext,
    upstream: UpstreamSource,
) -> Result<()> {
    run_vless_relay::<H3Ws>(H3Ws(socket), &server, &route, resume, upstream).await
}
