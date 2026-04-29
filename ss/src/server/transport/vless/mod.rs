use std::{sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use sockudo_ws::{Http3 as H3Transport, Stream as H3Stream, WebSocketStream as H3WebSocketStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::{
    metrics::{AppProtocol, Transport},
    protocol::vless::{self, VlessCommand, VlessUser, mask_uuid},
};

use super::super::{
    constants::{
        WS_CTRL_CHANNEL_CAPACITY, WS_PONG_DEADLINE_MULTIPLIER,
        WS_TCP_KEEPALIVE_PING_INTERVAL_SECS,
    },
    resumption::{Parked, ResumeOutcome, SessionId},
};
use super::sink;
use super::tcp::ResumeContext;
use super::vless_mux::{self, MuxRouteCtx, MuxServerCtx, MuxState};
use super::vless_udp::{self, forward_vless_udp_client_frames};
use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;

mod ctx;
mod tcp;
mod udp;

pub(in crate::server) use ctx::{VlessWsRouteCtx, VlessWsServerCtx};
pub(in crate::server::transport) use ctx::{
    UdpUpstream, UpstreamSession, VlessFrameError, VlessRelayOutcome, VlessRelayState,
    VlessWsOutbound,
};

use ctx::MAX_VLESS_HEADER_BUFFER;
use tcp::{establish_vless_tcp_upstream, shutdown_unparked_tcp, try_park_vless_tcp};
use udp::try_park_vless_udp_single;

async fn run_vless_relay<T: WsSocket>(
    socket: T,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    resume: ResumeContext,
) -> Result<()> {
    let (mut reader, writer) = socket.split_io();
    let (outbound_data_tx, outbound_data_rx) =
        mpsc::channel::<T::Msg>(server.ws_data_channel_capacity);
    let (outbound_ctrl_tx, outbound_ctrl_rx) = mpsc::channel::<T::Msg>(WS_CTRL_CHANNEL_CAPACITY);
    let writer_task = tokio::spawn(ws_writer::run_ws_writer::<T>(
        writer,
        outbound_ctrl_rx,
        outbound_data_rx,
        server.metrics.clone(),
        Transport::Tcp,
        route.protocol,
        AppProtocol::Vless,
    ));

    let ping_interval = Duration::from_secs(WS_TCP_KEEPALIVE_PING_INTERVAL_SECS);
    let pong_deadline = ping_interval * WS_PONG_DEADLINE_MULTIPLIER;
    let mut keepalive = tokio::time::interval(ping_interval);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;

    let mut state = VlessRelayState::new(resume);
    let mut client_closed = false;
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
                let msg = match result? {
                    Some(m) => m,
                    None => break,
                };
                last_inbound = std::time::Instant::now();
                match T::classify(msg) {
                    WsFrame::Binary(data) => {
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
            _ = keepalive.tick() => {
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

    // Try parking the TCP upstream into the orphan registry. Returns
    // `true` if the upstream and reader were moved to the registry; in
    // that case the regular shutdown branch below is skipped. UDP and
    // Mux paths are not parkable in the MVP and always fall through to
    // the legacy teardown.
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
                mux.shutdown().await;
            },
            UpstreamSession::Udp(_) | UpstreamSession::None => {},
        }
    }

    let _ = client_closed;
    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    let _ = writer_task.await;
    Ok(())
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
    match state.upstream {
        UpstreamSession::Tcp(_) => try_park_vless_tcp(state, server, route, session_id).await,
        UpstreamSession::Udp(_) => try_park_vless_udp_single(state, server, route, session_id).await,
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
        UpstreamSession::Mux(mux) => mux,
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
    server
        .orphan_registry
        .park(session_id, Parked::VlessMux(parked));
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
    use tokio::io::AsyncWriteExt;

    server.metrics.record_websocket_binary_frame(
        Transport::Tcp,
        route.protocol,
        AppProtocol::Vless,
        "in",
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
            tcp.writer
                .write_all(&data)
                .await
                .context("failed to write vless websocket data upstream")?;
            return Ok(());
        },
        UpstreamSession::Udp(udp) => {
            forward_vless_udp_client_frames(
                &mut udp.client_buffer,
                &data,
                udp.socket.as_ref(),
                counters,
                route.protocol,
                &route.path,
            )
            .await?;
            return Ok(());
        },
        UpstreamSession::Mux(mux) => {
            let mux_server = MuxServerCtx {
                dns_cache: Arc::clone(&server.dns_cache),
                prefer_ipv4_upstream: server.prefer_ipv4_upstream,
                outbound_ipv6: server.outbound_ipv6.clone(),
                metrics: Arc::clone(&server.metrics),
            };
            let mux_route = MuxRouteCtx {
                protocol: route.protocol,
                path: Arc::clone(&route.path),
            };
            vless_mux::handle_client_bytes(
                mux,
                &data,
                &mux_server,
                &mux_route,
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
            return Err(VlessFrameError::Fatal(anyhow!(
                "unsupported vless command {command:#x}"
            )));
        },
        Err(error) => {
            warn!(path = %route.path, error = %error, "vless parse error");
            return Err(VlessFrameError::Fatal(anyhow!(error)));
        },
    };

    let user = match vless::find_user(route.users.as_ref(), &request.user_id).cloned() {
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
            return Err(VlessFrameError::Fatal(anyhow!(
                "unknown vless user {masked}"
            )));
        },
    };

    match request.command {
        VlessCommand::Tcp => {
            establish_vless_tcp_upstream(state, request, user, server, route, outbound).await
        },
        VlessCommand::Udp => {
            vless_udp::establish_vless_udp_upstream(state, request, user, server, route, outbound)
                .await
        },
        VlessCommand::Mux => {
            establish_vless_mux_upstream(state, request, user, server, route, outbound).await
        },
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
    // Resume attempt: if the client offered a Session ID and the
    // registry has a parked VLESS-mux entry for this user, re-attach
    // every sub-connection atomically. The mux's request frame
    // arrives over the WS frame stream, so any leftover bytes after
    // the VLESS handshake are routed into the resumed mux just like
    // a fresh one.
    let user_id_for_resume = user.label_arc();
    if let Some(resume_id) = state.pending_resume_request.take()
        && let ResumeOutcome::Hit(parked_kind) =
            server.orphan_registry.take_for_resume(resume_id, &user_id_for_resume)
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
                    .send((outbound.make_binary)(Bytes::from_static(&[
                        vless::VERSION,
                        0x00,
                    ])))
                    .await
                    .map_err(|error| {
                        anyhow!("failed to queue vless mux response header on resume: {error}")
                    })?;

                let mux = vless_mux::attach_parked(
                    parked,
                    outbound.data_tx.clone(),
                    outbound.make_binary,
                    Arc::clone(&server.metrics),
                    route.protocol,
                );
                state.user_counters = Some(server.metrics.user_counters(&user.label_arc()));
                state.authenticated_user = Some(user);
                state.upstream = UpstreamSession::Mux(mux);

                // Forward any post-handshake bytes carried by the
                // current frame into the freshly-attached mux.
                let leftover = state.header_buffer.split_off(request.consumed);
                state.header_buffer.clear();
                if !leftover.is_empty()
                    && let UpstreamSession::Mux(mux) = &mut state.upstream
                {
                    let mux_server = MuxServerCtx {
                        dns_cache: Arc::clone(&server.dns_cache),
                        prefer_ipv4_upstream: server.prefer_ipv4_upstream,
                        outbound_ipv6: server.outbound_ipv6.clone(),
                        metrics: Arc::clone(&server.metrics),
                    };
                    let mux_route = MuxRouteCtx {
                        protocol: route.protocol,
                        path: Arc::clone(&route.path),
                    };
                    vless_mux::handle_client_bytes(
                        mux,
                        &leftover,
                        &mux_server,
                        &mux_route,
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
    let mut mux = MuxState::new(user.clone(), Arc::clone(&user_counters));
    state.user_counters = Some(user_counters);
    state.authenticated_user = Some(user);

    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    if !leftover.is_empty() {
        let mux_server = MuxServerCtx {
            dns_cache: Arc::clone(&server.dns_cache),
            prefer_ipv4_upstream: server.prefer_ipv4_upstream,
            outbound_ipv6: server.outbound_ipv6.clone(),
            metrics: Arc::clone(&server.metrics),
        };
        let mux_route = MuxRouteCtx {
            protocol: route.protocol,
            path: Arc::clone(&route.path),
        };
        vless_mux::handle_client_bytes(
            &mut mux,
            &leftover,
            &mux_server,
            &mux_route,
            outbound.data_tx,
            outbound.make_binary,
        )
        .await?;
    }

    state.upstream = UpstreamSession::Mux(mux);
    Ok(())
}

pub(super) async fn handle_vless_connection(
    socket: WebSocket,
    server: Arc<VlessWsServerCtx>,
    route: VlessWsRouteCtx,
    resume: ResumeContext,
) -> Result<()> {
    run_vless_relay::<AxumWs>(AxumWs(socket), &server, &route, resume).await
}

pub(in crate::server) async fn handle_vless_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<VlessWsServerCtx>,
    route: VlessWsRouteCtx,
    resume: ResumeContext,
) -> Result<()> {
    run_vless_relay::<H3Ws>(H3Ws(socket), &server, &route, resume).await
}
