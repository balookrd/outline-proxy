use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Notify, mpsc},
};
use tracing::{debug, info, warn};

use crate::{
    metrics::{AppProtocol, Metrics, Protocol, TcpUpstreamGuard},
    protocol::vless::{self, VlessUser},
};

use super::super::super::{
    abort::AbortOnDrop,
    connect::connect_tcp_target,
    relay::{GREEDY_DRAIN_TARGET, try_read_now_into_slice},
    resumption::{Parked, ParkedTcp, ResumeOutcome, SessionId, TcpProtocolContext},
    scratch::TcpRelayBuf,
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
pub(super) async fn shutdown_unparked_tcp(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    guard: TcpUpstreamGuard,
) {
    writer.shutdown().await.ok();
    guard.finish();
}

pub(super) async fn try_park_vless_tcp(
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
        owner: Arc::clone(&owner),
        // VLESS does not encrypt the relay payload, so the parked entry
        // carries no inner crypto context. Resume-attach on the VLESS
        // side just spawns a fresh raw-byte relay on the new client
        // stream.
        protocol_context: TcpProtocolContext::Vless,
        user_counters,
        upstream_guard: guard,
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
            let payload = crate::server::resumption::ack_prefix::build_v1_payload(
                state
                    .upstream_bytes_acked
                    .load(std::sync::atomic::Ordering::Relaxed),
            );
            let make_binary = outbound.make_binary;
            outbound
                .data_tx
                .send(make_binary(Bytes::copy_from_slice(&payload)))
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
            let (flags, payload, ring_diag) = match parked.downlink_ring.as_ref() {
                None => (0x01u8, Vec::new(), None),
                Some(ring) => {
                    let guard = ring.lock();
                    let diag = (guard.oldest_offset(), guard.total_sent());
                    let outcome = guard.replay_from(state.client_acked_offset_request);
                    drop(guard);
                    match outcome {
                        ReplayOutcome::Available(bytes) => (0x00u8, bytes, Some(diag)),
                        ReplayOutcome::Truncated => (0x01u8, Vec::new(), Some(diag)),
                        ReplayOutcome::OffsetAhead => {
                            warn!(
                                user = user.label(),
                                path = %route.path,
                                client_offset = state.client_acked_offset_request,
                                "v2 client claims more downstream bytes than server emitted; \
                                 treating as truncated"
                            );
                            (0x01u8, Vec::new(), Some(diag))
                        },
                    }
                },
            };
            let payload_len = payload.len() as u64;
            let truncated = (flags & 0x01) != 0;
            server
                .metrics
                .record_orphan_downlink_replay_bytes("tcp", payload_len);
            if truncated {
                server.metrics.record_orphan_downlink_replay_truncated("tcp");
            }
            let mut frame = Vec::with_capacity(14 + payload.len());
            frame.extend_from_slice(b"ORDR");
            frame.push(0x01); // version
            frame.push(flags);
            frame.extend_from_slice(&payload_len.to_be_bytes());
            frame.extend_from_slice(&payload);
            let make_binary = outbound.make_binary;
            outbound
                .data_tx
                .send(make_binary(Bytes::copy_from_slice(&frame)))
                .await
                .map_err(|error| {
                    anyhow!(
                        "failed to queue vless v2 downlink replay frame on resume: {error}"
                    )
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
                ring_for_task,
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
            ring_for_task,
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

async fn relay_vless_upstream_to_client<Msg>(
    mut upstream_reader: tokio::net::tcp::OwnedReadHalf,
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
) -> VlessRelayTaskOutput
where
    Msg: Send + 'static,
{
    let user_counters = metrics.user_counters(&user_id);
    let target_to_client = user_counters.tcp_out(AppProtocol::Vless, protocol);
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
                // Greedy-drain: see `relay::relay_upstream_to_client`.
                // VLESS-WS has no inner AEAD chunking, so the only
                // amortisation knob is mpsc push + ws-writer send +
                // TLS-record header per emitted frame. Pulling more
                // already-buffered upstream bytes into a single binary
                // frame collapses ~14k frames/sec at 200 Mbit into
                // ~1.5k while never yielding the runtime.
                let mut total = read;
                let cap = buffer.len().min(GREEDY_DRAIN_TARGET);
                while total < cap {
                    match try_read_now_into_slice(&mut upstream_reader, &mut buffer[total..cap])
                        .await
                        .context("failed to drain vless upstream")?
                    {
                        Some(0) => break,
                        Some(n) => total += n,
                        None => break,
                    }
                }
                target_to_client.increment(total as u64);
                // v2 capture: push plaintext into the ring BEFORE the
                // WS Binary send so `total_sent` always reflects what
                // the server has committed to send.
                if let Some(ring) = downlink_ring.as_ref() {
                    ring.lock().push(&buffer[..total]);
                }
                let used = tx.max_capacity().saturating_sub(tx.capacity());
                metrics.observe_ws_data_channel_fill(
                    crate::metrics::Transport::Tcp,
                    crate::metrics::AppProtocol::Vless,
                    used,
                );
                tx.send(make_binary(Bytes::copy_from_slice(&buffer[..total])))
                    .await
                    .map_err(|error| anyhow!("failed to queue vless websocket frame: {error}"))?;
            }
        }
    }
    let _ = tx.send(make_close()).await;
    Ok(VlessRelayOutcome::Closed)
}
