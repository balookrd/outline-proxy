use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::{Bytes, BytesMut};
use sockudo_ws::{Http3 as H3Transport, Stream as H3Stream, WebSocketStream as H3WebSocketStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::{Notify, mpsc},
};
use tracing::{debug, info, warn};

use crate::{
    metrics::{Metrics, PerUserCounters, Protocol, TcpUpstreamGuard, Transport},
    outbound::OutboundIpv6,
    protocol::vless::{self, VlessCommand, VlessUser, mask_uuid},
};

use super::{
    super::{
        abort::AbortOnDrop,
        connect::connect_tcp_target,
        constants::{
            WS_CTRL_CHANNEL_CAPACITY, WS_PONG_DEADLINE_MULTIPLIER,
            WS_TCP_KEEPALIVE_PING_INTERVAL_SECS,
        },
        dns_cache::DnsCache,
        resumption::{
            OrphanRegistry, Parked, ParkedTcp, ParkedVlessUdpSingle, ResumeOutcome, SessionId,
            TcpProtocolContext,
        },
        scratch::TcpRelayBuf,
    },
    sink,
    tcp::ResumeContext,
    vless_mux::{self, MuxRouteCtx, MuxServerCtx, MuxState},
    vless_udp::{self, forward_vless_udp_client_frames},
    ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket},
    ws_writer,
};

/// Outcome of [`relay_vless_upstream_to_client`] (TCP) and the
/// `vless_udp` / `vless_mux` helpers. Made `pub(super)` so the UDP
/// and Mux modules can construct the cancel variants when wrapping
/// their own relay task return values into [`VlessRelayTaskOutput`].
pub(super) enum VlessRelayOutcome {
    /// Upstream EOF or sink error; reader is consumed.
    Closed,
    /// TCP cancel: the caller fired the notify; the harvested
    /// `OwnedReadHalf` is returned for hand-off into the orphan
    /// registry.
    Cancelled(tokio::net::tcp::OwnedReadHalf),
    /// UDP cancel: nothing to harvest because the `Arc<UdpSocket>`
    /// already lives in `UpstreamSession::Udp`. The variant exists so
    /// the park path can tell "we asked it to stop" from "the upstream
    /// EOF'd on its own".
    UdpCancelled,
}

const MAX_VLESS_HEADER_BUFFER: usize = 512;

/// Failure modes returned by [`handle_vless_binary_frame`] and the upstream
/// establishers. [`run_vless_relay`] matches on this to decide whether to
/// send the client a "try again" close frame (RFC 6455 code 1013) — so the
/// client can retry on the same or a different uplink — or a plain close
/// for terminal errors (parser/auth/protocol). Mirrors `tcp::FrameError`.
pub(super) enum VlessFrameError {
    UpstreamConnectFailed(anyhow::Error),
    Fatal(anyhow::Error),
}

impl VlessFrameError {
    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::UpstreamConnectFailed(e) | Self::Fatal(e) => e,
        }
    }
}

impl From<anyhow::Error> for VlessFrameError {
    fn from(e: anyhow::Error) -> Self {
        Self::Fatal(e)
    }
}

pub(in crate::server) struct VlessWsServerCtx {
    pub(in crate::server) metrics: Arc<Metrics>,
    pub(in crate::server) dns_cache: Arc<DnsCache>,
    pub(in crate::server) prefer_ipv4_upstream: bool,
    pub(in crate::server) outbound_ipv6: Option<Arc<OutboundIpv6>>,
    /// Cross-transport session-resumption registry. No-op when disabled
    /// in config.
    pub(in crate::server) orphan_registry: Arc<OrphanRegistry>,
    /// Per-session bounded mpsc capacity for the upstream-reader →
    /// WS-writer fan-in. Resolved from `tuning.ws_data_channel_capacity`
    /// — sized too low and a momentary WS writer stall back-pressures
    /// the upstream TCP read, visible as video buffer underrun.
    pub(in crate::server) ws_data_channel_capacity: usize,
}

pub(in crate::server) struct VlessWsRouteCtx {
    pub(in crate::server) users: Arc<[VlessUser]>,
    pub(in crate::server) protocol: Protocol,
    pub(in crate::server) path: Arc<str>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
}

/// Return type of the VLESS-TCP relay task. Carries either a closed
/// outcome (no parking possible) or the harvested reader half so that
/// [`run_vless_relay`] can move it into the orphan registry on
/// disconnect.
type VlessRelayTaskOutput = Result<VlessRelayOutcome>;

/// Single-target VLESS-TCP upstream. Holds every TCP-only piece of
/// state — none of these fields are meaningful for UDP or Mux, so
/// packing them here lets the type system enforce the invariant.
pub(super) struct TcpUpstream {
    pub(super) writer: tokio::net::tcp::OwnedWriteHalf,
    /// `AbortOnDrop` ensures the upstream→client task is cancelled on
    /// every exit path of the owning `run_vless_relay` future,
    /// including `?`-returns and panics.
    pub(super) reader_task: AbortOnDrop<VlessRelayTaskOutput>,
    /// Notify used to ask the spawned reader to stop and hand over its
    /// read half on park-on-drop.
    pub(super) cancel: Arc<Notify>,
    /// Human-readable target host:port. Used for logging and to
    /// populate `ParkedTcp::target_display` on park.
    pub(super) target_display: Arc<str>,
    pub(super) guard: TcpUpstreamGuard,
}

/// Single-target VLESS-UDP upstream. UDP-only counterpart of
/// [`TcpUpstream`].
pub(super) struct UdpUpstream {
    pub(super) socket: Arc<UdpSocket>,
    /// See [`TcpUpstream::reader_task`]. Critical for UDP because
    /// `socket.recv` has no shutdown signal — without `AbortOnDrop`
    /// the reader would block forever and orphan its `Arc<UdpSocket>`
    /// + 64 KiB buffer.
    pub(super) reader_task: AbortOnDrop<VlessRelayTaskOutput>,
    pub(super) cancel: Arc<Notify>,
    pub(super) target_display: Arc<str>,
    /// Partial-frame reassembly buffer for the 2-byte-length-prefixed
    /// VLESS-UDP framing.
    pub(super) client_buffer: BytesMut,
}

pub(super) enum UpstreamSession {
    None,
    Tcp(TcpUpstream),
    Udp(UdpUpstream),
    Mux(MuxState),
}

pub(super) struct VlessRelayState {
    pub(super) header_buffer: Vec<u8>,
    pub(super) upstream: UpstreamSession,
    pub(super) authenticated_user: Option<VlessUser>,
    pub(super) user_counters: Option<Arc<PerUserCounters>>,
    /// Session ID we minted at WS-Upgrade time and surfaced via
    /// `X-Outline-Session`. Used as the registry key on park.
    pub(super) issued_session_id: Option<SessionId>,
    /// Session ID the client offered for resumption. Consumed (`take()`)
    /// on the first authenticated VLESS-TCP / VLESS-UDP / VLESS-MUX frame.
    pub(super) pending_resume_request: Option<SessionId>,
}

pub(super) struct VlessWsOutbound<'a, Msg> {
    pub(super) data_tx: &'a mpsc::Sender<Msg>,
    pub(super) make_binary: fn(Bytes) -> Msg,
    pub(super) make_close: fn() -> Msg,
}

impl VlessRelayState {
    fn new(resume: ResumeContext) -> Self {
        Self {
            header_buffer: Vec::with_capacity(128),
            upstream: UpstreamSession::None,
            authenticated_user: None,
            user_counters: None,
            issued_session_id: resume.issued_session_id,
            pending_resume_request: resume.requested_resume,
        }
    }
}

/// Graceful close of a TCP upstream that was extracted from
/// [`UpstreamSession::Tcp`] but never made it into the orphan
/// registry (park aborted, harvest race, no authenticated user).
/// Mirrors the cleanup that [`run_vless_relay`] runs on the unparked
/// path so that `try_park_*` early-returns don't degrade FIN→RST or
/// drop the gauge silently.
async fn shutdown_unparked_tcp(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    guard: TcpUpstreamGuard,
) {
    writer.shutdown().await.ok();
    guard.finish();
}

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

/// Atomic park of a single-target VLESS-UDP-over-WS session. Consumes
/// the `Arc<UdpSocket>` from `state.upstream` and inserts a
/// [`Parked::VlessUdpSingle`] entry. The reader task is asked to stop
/// via `cancel.notify_one()` (it acknowledges with
/// [`VlessRelayOutcome::UdpCancelled`]); the socket itself rides into
/// the registry untouched.
async fn try_park_vless_udp_single(
    state: &mut VlessRelayState,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    session_id: SessionId,
) -> bool {
    let UdpUpstream {
        socket,
        reader_task,
        cancel,
        target_display,
        client_buffer,
    } = match std::mem::replace(&mut state.upstream, UpstreamSession::None) {
        UpstreamSession::Udp(udp) => udp,
        other => {
            // Shouldn't happen given the caller's match.
            state.upstream = other;
            return false;
        },
    };
    cancel.notify_one();
    match reader_task.into_inner().await {
        Ok(Ok(VlessRelayOutcome::UdpCancelled)) => {},
        Ok(Ok(VlessRelayOutcome::Closed)) => return false,
        Ok(Ok(VlessRelayOutcome::Cancelled(_))) => {
            // Reserved for the TCP harvest path; should never fire here.
            return false;
        },
        Ok(Err(error)) => {
            debug!(?error, "vless udp relay task errored before park; not parking");
            return false;
        },
        Err(join_error) => {
            warn!(?join_error, "vless udp relay task panicked during harvest");
            return false;
        },
    }
    let user = match state.authenticated_user.take() {
        Some(user) => user,
        None => return false,
    };
    let user_counters = match state.user_counters.take() {
        Some(c) => c,
        None => {
            state.authenticated_user = Some(user);
            return false;
        },
    };
    let owner = user.label_arc();
    // We don't have a `TargetAddr` to hand back — `request.target` was
    // consumed in `establish_vless_udp_upstream`. Reconstruct from the
    // socket's connected peer for a faithful `target` field.
    let target = match socket.peer_addr() {
        Ok(addr) => crate::protocol::TargetAddr::Socket(addr),
        Err(_) => crate::protocol::TargetAddr::Domain(target_display.to_string(), 0),
    };
    let parked = ParkedVlessUdpSingle {
        socket: Arc::clone(&socket),
        target,
        target_display,
        protocol: route.protocol,
        owner: Arc::clone(&owner),
        user: user.clone(),
        user_counters,
        udp_client_buffer: client_buffer,
    };
    debug!(
        user = %owner,
        path = %route.path,
        "parking vless udp single upstream into orphan registry",
    );
    server
        .orphan_registry
        .park(session_id, Parked::VlessUdpSingle(parked));
    state.authenticated_user = Some(user);
    true
}

async fn try_park_vless_tcp(
    state: &mut VlessRelayState,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    session_id: SessionId,
) -> bool {
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
        Ok(Ok(VlessRelayOutcome::Cancelled(reader))) => reader,
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
    let owner = user.label_arc();
    let parked = ParkedTcp {
        upstream_writer: writer,
        upstream_reader: reader,
        target_display,
        protocol: route.protocol,
        owner: Arc::clone(&owner),
        // VLESS does not encrypt the relay payload, so the parked entry
        // carries no inner crypto context. Resume-attach on the VLESS
        // side just spawns a fresh raw-byte relay on the new client
        // stream.
        protocol_context: TcpProtocolContext::Vless,
        user_counters,
        upstream_guard: guard,
    };
    debug!(
        user = %owner,
        path = %route.path,
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
    let parked = mux
        .harvest_into_parked(Arc::clone(&owner), route.protocol)
        .await;
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
    server
        .metrics
        .record_websocket_binary_frame(Transport::Tcp, route.protocol, "in", data.len());

    let counters = state.user_counters.as_deref();
    match &mut state.upstream {
        UpstreamSession::Tcp(tcp) => {
            if let Some(counters) = counters {
                counters.tcp_in(route.protocol).increment(data.len() as u64);
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

async fn establish_vless_tcp_upstream<Msg>(
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
    let target_display = target.display_host_port();
    info!(user = user.label(), path = %route.path, target = %target_display, "vless tcp target");

    // Resume attempt: re-attach to a parked VLESS-TCP upstream when the
    // client offered a Session ID that this user owns. The target sent
    // in the VLESS request is intentionally ignored on a hit — by spec
    // the parked target is authoritative.
    let user_id_for_resume = user.label_arc();
    if let Some(resume_id) = state.pending_resume_request.take()
        && let ResumeOutcome::Hit(Parked::Tcp(parked)) =
            server.orphan_registry.take_for_resume(resume_id, &user_id_for_resume)
    {
        let TcpProtocolContext::Vless = parked.protocol_context else {
            warn!(
                user = user.label(),
                path = %route.path,
                parked_kind = parked.protocol_context.label(),
                "rejecting resume: parked session belongs to a different proxy protocol"
            );
            return Err(VlessFrameError::Fatal(anyhow!(
                "cross-protocol resume rejected: parked session is not VLESS"
            )));
        };
        info!(
            user = user.label(),
            path = %route.path,
            target = %parked.target_display,
            "vless tcp upstream resumed from orphan registry"
        );
        // Send the standard VLESS response header so the client moves
        // its parser past the handshake before receiving payload.
        outbound
            .data_tx
            .send((outbound.make_binary)(Bytes::from_static(&[vless::VERSION, 0x00])))
            .await
            .map_err(|error| anyhow!("failed to queue vless response header on resume: {error}"))?;

        let tx = outbound.data_tx.clone();
        let metrics = Arc::clone(&server.metrics);
        let user_id_for_relay = Arc::clone(&user_id_for_resume);
        let protocol = route.protocol;
        let cancel = Arc::new(Notify::new());
        let cancel_for_task = Arc::clone(&cancel);
        let parked_reader = parked.upstream_reader;
        let make_binary = outbound.make_binary;
        let make_close = outbound.make_close;
        let reader_task = AbortOnDrop::new(tokio::spawn(async move {
            relay_vless_upstream_to_client(
                parked_reader,
                tx,
                make_binary,
                make_close,
                metrics,
                protocol,
                user_id_for_relay,
                Some(cancel_for_task),
            )
            .await
        }));
        state.user_counters = Some(parked.user_counters);
        state.authenticated_user = Some(user);
        state.upstream = UpstreamSession::Tcp(TcpUpstream {
            writer: parked.upstream_writer,
            reader_task,
            cancel,
            target_display: parked.target_display,
            guard: parked.upstream_guard,
        });

        // Forward any payload bytes that arrived in the same WS frame
        // as the VLESS request header.
        let leftover = state.header_buffer.split_off(request.consumed);
        state.header_buffer.clear();
        if !leftover.is_empty()
            && let UpstreamSession::Tcp(tcp) = &mut state.upstream
        {
            if let Some(counters) = &state.user_counters {
                counters.tcp_in(route.protocol).increment(leftover.len() as u64);
            }
            tcp.writer
                .write_all(&leftover)
                .await
                .context("failed to write initial vless payload upstream after resume")?;
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
                "success",
                connect_started.elapsed().as_secs_f64(),
            );
            stream
        },
        Err(error) => {
            server.metrics.record_tcp_connect(
                user.label_arc(),
                route.protocol,
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
        .send((outbound.make_binary)(Bytes::from_static(&[vless::VERSION, 0x00])))
        .await
        .map_err(|error| anyhow!("failed to queue vless response header: {error}"))?;

    let tx = outbound.data_tx.clone();
    let metrics = Arc::clone(&server.metrics);
    let user_id = user.label_arc();
    let protocol = route.protocol;
    // Cancel-notify is registered unconditionally so park-on-drop can
    // harvest the reader. When resumption is disabled the notify is
    // simply never fired and the relay loop runs in its single-arm
    // (legacy) mode.
    let cancel = Arc::new(Notify::new());
    let cancel_for_task = Arc::clone(&cancel);
    let reader_task = AbortOnDrop::new(tokio::spawn(async move {
        relay_vless_upstream_to_client(
            upstream_reader,
            tx,
            outbound.make_binary,
            outbound.make_close,
            metrics,
            protocol,
            user_id,
            Some(cancel_for_task),
        )
        .await
    }));
    server
        .metrics
        .record_tcp_authenticated_session(user.label_arc(), route.protocol);
    let guard = server
        .metrics
        .open_tcp_upstream_connection(user.label_arc(), route.protocol);
    state.user_counters = Some(server.metrics.user_counters(&user.label_arc()));
    state.authenticated_user = Some(user);
    state.upstream = UpstreamSession::Tcp(TcpUpstream {
        writer,
        reader_task,
        cancel,
        target_display: Arc::from(target_display.as_str()),
        guard,
    });

    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    if !leftover.is_empty()
        && let UpstreamSession::Tcp(tcp) = &mut state.upstream
    {
        if let Some(counters) = &state.user_counters {
            counters.tcp_in(route.protocol).increment(leftover.len() as u64);
        }
        tcp.writer
            .write_all(&leftover)
            .await
            .context("failed to write initial vless payload upstream")?;
    }

    Ok(())
}

async fn relay_vless_upstream_to_client<Msg>(
    mut upstream_reader: tokio::net::tcp::OwnedReadHalf,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user_id: Arc<str>,
    cancel: Option<Arc<Notify>>,
) -> VlessRelayTaskOutput
where
    Msg: Send + 'static,
{
    let user_counters = metrics.user_counters(&user_id);
    let target_to_client = user_counters.tcp_out(protocol);
    let mut buffer = TcpRelayBuf::take();
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
                return Ok(VlessRelayOutcome::Cancelled(upstream_reader));
            }
            read_result = upstream_reader.read(&mut *buffer) => {
                let read = read_result.context("failed to read from vless upstream")?;
                if read == 0 {
                    break;
                }
                target_to_client.increment(read as u64);
                tx.send(make_binary(Bytes::copy_from_slice(&buffer[..read])))
                    .await
                    .map_err(|error| anyhow!("failed to queue vless websocket frame: {error}"))?;
            }
        }
    }
    let _ = tx.send(make_close()).await;
    Ok(VlessRelayOutcome::Closed)
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
