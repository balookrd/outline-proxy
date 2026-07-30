use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
};
use tracing::{debug, warn};

use outline_wire::padding::PaddingScheme;

use crate::{
    fwmark::apply_fwmark_if_needed,
    metrics::{AppProtocol, Metrics, PerUserCounters, Protocol},
    outbound::OutboundIpv6,
    protocol::vless::{self, VlessUser},
};

use crate::server::cluster::mesh::read_datagram;

use super::carrier_padding;
use super::upstream_source::{MeshDatagramHalves, MeshUpstreamSetup, VlessUdpSink};
use super::{
    super::{
        abort::AbortOnDrop,
        connect::resolve_udp_target,
        constants::MAX_UDP_PAYLOAD_SIZE,
        nat::bind_nat_udp_socket,
        resumption::{Parked, ResumeOutcome},
        scratch::UdpRecvBuf,
    },
    vless::{
        UdpUpstream, UpstreamSession, VlessFrameError, VlessRelayOutcome, VlessRelayState,
        VlessWsOutbound, VlessWsRouteCtx, VlessWsServerCtx,
    },
};

pub(super) const MAX_VLESS_UDP_CLIENT_BUFFER: usize = MAX_UDP_PAYLOAD_SIZE + 2;

pub(super) async fn establish_vless_udp_upstream<Msg>(
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

    // Cluster edge: the socket lives on the home, which acked this relay for a
    // single-target VLESS-UDP park and is still waiting to be told *who* it is
    // resuming. Neither the local registry nor a bind is consulted — the home
    // owns both, and the target parsed above is deliberately ignored for the
    // same reason a local resume hit ignores it: the parked target is
    // authoritative, and the parked socket is already connected to it.
    if let Some(setup) = state.mesh_upstream.take() {
        return attach_mesh_udp_upstream(state, setup, request, user, server, route, outbound)
            .await;
    }

    // Resume attempt: re-attach a parked single-target VLESS-UDP
    // session before doing any DNS / bind work. The target sent in
    // this VLESS request is intentionally ignored on a hit — by spec
    // the parked target is authoritative.
    let user_id_for_resume = user.label_arc();
    if let Some(resume_id) = state.pending_resume_request.take()
        && let ResumeOutcome::Hit(parked_kind) = server
            .orphan_registry
            .take_for_resume(resume_id, &user_id_for_resume)
            .await
    {
        match parked_kind {
            Parked::VlessUdpSingle(parked) => {
                debug!(
                    user = user.label(),
                    path = %route.path,
                    target = %parked.target_display,
                    "vless udp single upstream resumed from orphan registry"
                );
                outbound
                    .data_tx
                    .send((outbound.make_binary)(carrier_padding::frame_downlink_message(
                        route.padding,
                        Bytes::from_static(&[vless::VERSION, 0x00]),
                    )))
                    .await
                    .map_err(|error| {
                        anyhow!("failed to queue vless udp response header on resume: {error}")
                    })?;

                let reader_socket = Arc::clone(&parked.socket);
                let tx = outbound.data_tx.clone();
                let metrics = Arc::clone(&server.metrics);
                let user_id = parked.user.label_arc();
                let protocol = route.protocol;
                let padding = route.padding;
                let cancel = Arc::new(Notify::new());
                let cancel_for_task = Arc::clone(&cancel);
                let monitor_for_task = state.throttle_monitor.clone();
                let reader_task = AbortOnDrop::new(tokio::spawn(async move {
                    relay_vless_udp_upstream_to_client(
                        reader_socket,
                        tx,
                        outbound.make_binary,
                        outbound.make_close,
                        metrics,
                        protocol,
                        user_id,
                        Some(cancel_for_task),
                        padding,
                        monitor_for_task,
                    )
                    .await
                }));
                state.user_counters = Some(parked.user_counters);
                state.authenticated_user = Some(parked.user);
                state.upstream = UpstreamSession::Udp(UdpUpstream {
                    sink: VlessUdpSink::Socket(parked.socket),
                    reader_task,
                    cancel,
                    target_display: parked.target_display,
                    client_buffer: parked.udp_client_buffer,
                });

                // Forward any payload that piggy-backed on the resume
                // request frame.
                let leftover = state.header_buffer.split_off(request.consumed);
                state.header_buffer.clear();
                let counters = state.user_counters.as_deref();
                if !leftover.is_empty()
                    && let UpstreamSession::Udp(udp) = &mut state.upstream
                {
                    let leftover_bytes = Bytes::from(leftover);
                    forward_vless_udp_client_frames(
                        &mut udp.client_buffer,
                        &leftover_bytes,
                        &mut udp.sink,
                        counters,
                        route.protocol,
                        &route.path,
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
                    "rejecting vless udp resume: parked entry is not single-target VLESS-UDP"
                );
                return Err(VlessFrameError::Fatal(anyhow!(
                    "cross-shape resume rejected: parked session kind is {}, not vless_udp_single",
                    other.kind(),
                )));
            },
        }
    }

    debug!(user = user.label(), path = %route.path, target = %target_display, "vless udp target");

    let resolved =
        match resolve_udp_target(server.dns_cache.as_ref(), &target, server.prefer_ipv4_upstream)
            .await
        {
            Ok(addr) => addr,
            Err(error) => {
                warn!(
                    user = user.label(),
                    path = %route.path,
                    target = %target_display,
                    error = %error,
                    "vless udp dns resolution failed; sending try-again close"
                );
                return Err(VlessFrameError::UpstreamConnectFailed(
                    error.context("vless udp dns resolution failed"),
                ));
            },
        };

    let socket = match bind_and_connect_udp(
        resolved,
        user.fwmark(),
        server.outbound_ipv6.as_deref(),
    )
    .await
    {
        Ok(socket) => socket,
        Err(error) => {
            warn!(
                user = user.label(),
                path = %route.path,
                target = %target_display,
                error = %error,
                "vless udp bind/connect failed; sending try-again close"
            );
            return Err(VlessFrameError::UpstreamConnectFailed(
                error.context("vless udp upstream bind/connect failed"),
            ));
        },
    };

    let socket = Arc::new(socket);

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
    let reader_socket = Arc::clone(&socket);
    // Cancel-notify is registered unconditionally so park-on-drop can
    // ask the reader to stop and (for UDP) signal `UdpCancelled`. When
    // resumption is disabled the notify is simply never fired.
    let cancel = Arc::new(Notify::new());
    let cancel_for_task = Arc::clone(&cancel);
    let monitor_for_task = state.throttle_monitor.clone();
    let reader_task = AbortOnDrop::new(tokio::spawn(async move {
        relay_vless_udp_upstream_to_client(
            reader_socket,
            tx,
            outbound.make_binary,
            outbound.make_close,
            metrics,
            protocol,
            user_id,
            Some(cancel_for_task),
            padding,
            monitor_for_task,
        )
        .await
    }));
    state.user_counters = Some(server.metrics.user_counters(&user.label_arc()));
    state.authenticated_user = Some(user);
    state.upstream = UpstreamSession::Udp(UdpUpstream {
        sink: VlessUdpSink::Socket(socket),
        reader_task,
        cancel,
        target_display: Arc::from(target_display.as_str()),
        client_buffer: BytesMut::new(),
    });

    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    let counters = state.user_counters.as_deref();
    if !leftover.is_empty()
        && let UpstreamSession::Udp(udp) = &mut state.upstream
    {
        let leftover_bytes = Bytes::from(leftover);
        forward_vless_udp_client_frames(
            &mut udp.client_buffer,
            &leftover_bytes,
            &mut udp.sink,
            counters,
            route.protocol,
            &route.path,
        )
        .await?;
    }

    Ok(())
}

async fn bind_and_connect_udp(
    target: SocketAddr,
    fwmark: Option<u32>,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<UdpSocket> {
    let socket = bind_nat_udp_socket(target, outbound_ipv6)
        .context("failed to bind vless udp upstream socket")?;
    apply_fwmark_if_needed(&socket, fwmark)
        .with_context(|| format!("failed to apply fwmark {fwmark:?} to vless udp socket"))?;
    socket
        .connect(&target)
        .await
        .with_context(|| format!("failed to connect vless udp socket to {target}"))?;
    Ok(socket)
}

/// De-frames the client's `u16`-length-prefixed VLESS-UDP uplink and sends each
/// datagram whole.
///
/// One client frame is one `sink.send`, and that is the contract the whole path
/// rests on: a datagram is atomic, and two of them merged into one send arrive
/// at the target as a single corrupt packet. It holds for both sinks — a local
/// socket sends one datagram, a mesh relay writes one length-framed one.
///
/// Per-user accounting happens **here**, on the node that terminates the client
/// session; a relayed session's home deliberately counts this traffic only on
/// its `role="home"` mesh counters.
pub(super) async fn forward_vless_udp_client_frames(
    buffer: &mut BytesMut,
    data: &Bytes,
    sink: &mut VlessUdpSink,
    user_counters: Option<&PerUserCounters>,
    protocol: Protocol,
    path: &str,
) -> Result<()> {
    buffer.extend_from_slice(data);
    loop {
        if buffer.len() < 2 {
            break;
        }
        let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
        if len > MAX_UDP_PAYLOAD_SIZE {
            warn!(path = %path, len, "vless udp client datagram exceeds maximum; dropping session");
            return Err(anyhow!("vless udp datagram too large: {len}"));
        }
        if buffer.len() < 2 + len {
            if buffer.capacity() < 2 + len {
                buffer.reserve(2 + len - buffer.capacity());
            }
            break;
        }
        let _ = buffer.split_to(2);
        let payload = buffer.split_to(len).freeze();
        if let Some(counters) = user_counters {
            counters
                .udp_in(AppProtocol::Vless, protocol)
                .increment(payload.len() as u64);
        }
        if let Err(error) = sink.send(&payload).await {
            warn!(path = %path, error = %error, "vless udp send failed");
            return Err(error);
        }
    }
    if buffer.len() > MAX_VLESS_UDP_CLIENT_BUFFER {
        return Err(anyhow!("vless udp client buffer overflow: {}", buffer.len()));
    }
    Ok(())
}

/// Cluster edge: completes the v5 mesh hand-off for a VLESS-UDP session whose
/// socket lives on the home, and wires the mesh stream in where that socket
/// would be.
///
/// Runs the second phase of the two-phase OPEN. The home acked phase 1 with
/// [`MeshShape::VlessUdpSingle`] — "I hold a single-target VLESS-UDP park under
/// this id" — before the client carrier was upgraded, and the dispatch in
/// `vless` only routes a `Udp` command here when that is what it was told. Only
/// now, with the client authenticated against **this node's** VLESS credentials,
/// can the edge name the user, so the USER frame goes out here and the home
/// answers the owner check by either splicing the park onto the stream or
/// resetting it.
///
/// The client's UUID is matched against this edge's own route, which is why the
/// home's need not be the same one: the mesh carries VLESS *payload*, not the
/// VLESS handshake, so the two nodes authenticate independently. The standard
/// `[VERSION, 0x00]` response header is therefore emitted here too.
///
/// No Ack-Prefix control frame follows it, exactly as on the direct VLESS-UDP
/// path: v1 is a byte-stream feature and a datagram session has no uplink offset
/// to be short of. The home still sends its [`UpstreamAckFrame`] when the OPEN
/// asked for one — `attach_datagrams` consumes it, or the first datagram's
/// length prefix would be read out of that frame's bytes — and its `0` is
/// discarded here.
///
/// [`MeshShape::VlessUdpSingle`]: crate::server::cluster::mesh::MeshShape::VlessUdpSingle
/// [`UpstreamAckFrame`]: crate::server::cluster::mesh::UpstreamAckFrame
async fn attach_mesh_udp_upstream<Msg>(
    state: &mut VlessRelayState,
    setup: MeshUpstreamSetup,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    outbound: VlessWsOutbound<'_, Msg>,
) -> Result<(), VlessFrameError>
where
    Msg: Send + 'static,
{
    let user_id = user.label_arc();
    // For logs only, and deliberately the target the *client* asked for: the
    // home's parked socket is already connected to the target it was minted for,
    // and that one is authoritative.
    let target_display: Arc<str> = Arc::from(request.target.to_string().as_str());
    // A hand-off that fails here — the home refused the owner check, or the mesh
    // broke — is retryable, not a protocol fault: the client is authenticated,
    // so it gets a "try again" close and reconnects. `Fatal` would instead run
    // the anti-fingerprinting inbound sink, which exists for unauthenticated
    // probes. Mirrors the byte-stream edge's `attach_mesh_upstream`.
    let MeshDatagramHalves {
        send,
        recv,
        budget,
        up_bytes,
        up_datagrams,
        down_bytes,
        down_datagrams,
        permit,
    } = setup.attach_datagrams(&user_id).await.map_err(|error| {
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
            anyhow!("failed to queue vless udp response header for a relayed session: {error}")
        })?;

    debug!(
        user = user.label(),
        path = %route.path,
        target = %target_display,
        "vless udp session relayed to its home; this node terminates the client crypto",
    );

    let tx = outbound.data_tx.clone();
    let metrics = Arc::clone(&server.metrics);
    let user_id_for_relay = Arc::clone(&user_id);
    let protocol = route.protocol;
    let padding = route.padding;
    let monitor_for_task = state.throttle_monitor.clone();
    let make_binary = outbound.make_binary;
    let make_close = outbound.make_close;
    let permit_for_task = Arc::clone(&permit);
    // Registered as on the direct path, though nothing here ever parks: a
    // relayed session's socket lives on the home. The reader is `AbortOnDrop`,
    // which is what stops it when the carrier goes away.
    let cancel = Arc::new(Notify::new());
    let reader_task = AbortOnDrop::new(tokio::spawn(async move {
        relay_mesh_udp_to_client(
            recv,
            MeshUdpDownlink {
                tx,
                make_binary,
                make_close,
                metrics,
                protocol,
                user_id: user_id_for_relay,
                padding,
                monitor: monitor_for_task,
                down_bytes,
                down_datagrams,
                _permit: permit_for_task,
            },
        )
        .await
    }));
    state.user_counters = Some(server.metrics.user_counters(&user_id));
    state.authenticated_user = Some(user);
    state.upstream = UpstreamSession::Udp(UdpUpstream {
        sink: VlessUdpSink::Mesh {
            send,
            budget,
            bytes: up_bytes,
            datagrams: up_datagrams,
            _permit: permit,
        },
        reader_task,
        cancel,
        target_display,
        client_buffer: BytesMut::new(),
    });

    // Forward any payload that piggy-backed on the request frame.
    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    let counters = state.user_counters.as_deref();
    if !leftover.is_empty()
        && let UpstreamSession::Udp(udp) = &mut state.upstream
    {
        let leftover_bytes = Bytes::from(leftover);
        forward_vless_udp_client_frames(
            &mut udp.client_buffer,
            &leftover_bytes,
            &mut udp.sink,
            counters,
            route.protocol,
            &route.path,
        )
        .await
        .map_err(|error| {
            VlessFrameError::UpstreamConnectFailed(
                error.context("failed to relay the initial vless udp payload over the mesh"),
            )
        })?;
    }
    Ok(())
}

/// Everything the relayed VLESS-UDP downlink pump needs, minus the stream half
/// it reads from.
struct MeshUdpDownlink<Msg> {
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user_id: Arc<str>,
    /// Carrier-padding scheme for this path; disabled → plain wire.
    padding: PaddingScheme,
    /// Per-carrier downstream-throttle monitor; `Some` only on a padded path
    /// with detection on. This node owns the last mile to the client even
    /// though it owns no socket, so the detection is local exactly as on a
    /// direct carrier.
    monitor: Option<Arc<super::throughput_monitor::ThroughputMonitor>>,
    down_bytes: metrics::Counter,
    down_datagrams: metrics::Counter,
    /// Keeps the relay's pool slot counted for as long as this half lives.
    _permit: Arc<tokio::sync::OwnedSemaphorePermit>,
}

/// Drains relayed datagrams off the mesh and frames each one for the client.
///
/// One datagram in is one `u16`-length-prefixed VLESS frame out: the mesh's own
/// length framing is what preserves the boundary across the hop, and coalescing
/// two would hand the client a single oversized datagram it cannot split back
/// apart. Bounded on every axis: the read caps each datagram at the framing's
/// own maximum, one reusable buffer serves the whole pump, and the client-facing
/// send rides the carrier's bounded channel.
///
/// Per-user accounting happens **here**, not on the home: this is the node that
/// terminates the client session, and the home's splice deliberately emits no
/// `user`-labelled series for a relayed one.
async fn relay_mesh_udp_to_client<Msg>(
    mut recv: quinn::RecvStream,
    ctx: MeshUdpDownlink<Msg>,
) -> Result<VlessRelayOutcome>
where
    Msg: Send + 'static,
{
    let user_counters = ctx.metrics.user_counters(&ctx.user_id);
    let target_to_client = user_counters.udp_out(AppProtocol::Vless, ctx.protocol);
    let mut buf = Vec::new();
    loop {
        let len = match read_datagram(&mut recv, &mut buf).await {
            // The home finished the stream: the relayed session is over.
            Ok(None) => break,
            Ok(Some(len)) => len,
            Err(error) => {
                debug!(?error, "relayed vless udp downlink read from the mesh ended");
                break;
            },
        };
        ctx.down_bytes.increment(len as u64);
        ctx.down_datagrams.increment(1);
        // The client's framing carries a `u16` length, so a datagram past the
        // UDP maximum could not be expressed to it at all — it would wrap and
        // the client would mis-frame every byte after it. Nothing this side of
        // the mesh can produce one (the home reads from a UDP socket), so this
        // guards against a peer, not against ourselves.
        if len > MAX_UDP_PAYLOAD_SIZE {
            warn!(len, "dropping an oversized relayed vless udp datagram");
            continue;
        }
        target_to_client.increment(len as u64);
        if let Some(monitor) = ctx.monitor.as_ref() {
            monitor.add_inbound(len as u64);
            let used = ctx.tx.max_capacity().saturating_sub(ctx.tx.capacity());
            if used.saturating_mul(2) >= ctx.tx.max_capacity() {
                monitor.note_backlog();
            }
        }
        // The client's own framing, rebuilt on this side of the mesh: the edge
        // terminates VLESS, so the home never sees these two bytes.
        let mut framed = BytesMut::with_capacity(2 + len);
        framed.put_u16(len as u16);
        framed.extend_from_slice(&buf[..len]);
        let datagram = carrier_padding::frame_downlink_message(ctx.padding, framed.freeze());
        if ctx.tx.send((ctx.make_binary)(datagram)).await.is_err() {
            debug!("relayed vless udp response dropped: the client carrier is gone");
            return Ok(VlessRelayOutcome::Closed);
        }
    }
    let _ = ctx.tx.send((ctx.make_close)()).await;
    Ok(VlessRelayOutcome::Closed)
}

#[allow(clippy::too_many_arguments)]
async fn relay_vless_udp_upstream_to_client<Msg>(
    socket: Arc<UdpSocket>,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user_id: Arc<str>,
    cancel: Option<Arc<Notify>>,
    // Carrier-padding scheme for this path; disabled → plain wire.
    padding: PaddingScheme,
    // Per-carrier downstream-throttle monitor; `Some` only on a padded path
    // with detection on. Fed inbound (from-internet) bytes + send backlog. The
    // control frame + outbound side are fed by the shared `run_ws_writer`.
    monitor: Option<Arc<super::throughput_monitor::ThroughputMonitor>>,
) -> Result<VlessRelayOutcome>
where
    Msg: Send + 'static,
{
    let user_counters = metrics.user_counters(&user_id);
    let target_to_client = user_counters.udp_out(AppProtocol::Vless, protocol);
    loop {
        let cancelled = async {
            match cancel.as_deref() {
                Some(notify) => notify.notified().await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            _ = cancelled => {
                // Park: the `Arc<UdpSocket>` already lives in
                // `UpstreamSession::Udp` so the caller can move it into
                // the orphan registry. We do not push a Close frame —
                // a resume would race against it.
                return Ok(VlessRelayOutcome::UdpCancelled);
            }
            ready = socket.readable() => {
                if let Err(error) = ready {
                    let _ = tx.send(make_close()).await;
                    return Err(error).context("failed to await vless udp upstream");
                }
                // Allocate from the pool only once a datagram is ready, so an
                // idle UDP relay holds no per-session receive buffer; the
                // buffer returns to the pool before the next park.
                let mut buffer = UdpRecvBuf::take();
                let read = match socket.try_recv(&mut buffer) {
                    Ok(n) => n,
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => {
                        let _ = tx.send(make_close()).await;
                        return Err(error).context("failed to read from vless udp upstream");
                    },
                };
                if read == 0 {
                    continue;
                }
                target_to_client.increment(read as u64);
                // Throttle detection: count bytes pulled from the internet
                // (inbound) and note a send backlog (data channel past
                // half-full) for this UDP carrier.
                if let Some(m) = monitor.as_ref() {
                    m.add_inbound(read as u64);
                    let used = tx.max_capacity().saturating_sub(tx.capacity());
                    if used.saturating_mul(2) >= tx.max_capacity() {
                        m.note_backlog();
                    }
                }
                let mut framed = BytesMut::with_capacity(2 + read);
                framed.put_u16(read as u16);
                framed.extend_from_slice(&buffer[..read]);
                let datagram = carrier_padding::frame_downlink_message(padding, framed.freeze());
                tx.send(make_binary(datagram)).await.map_err(|error| {
                    anyhow!("failed to queue vless udp websocket frame: {error}")
                })?;
            }
        }
    }
}
