use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use sockudo_ws::{Http3 as H3Transport, Stream as H3Stream, WebSocketStream as H3WebSocketStream};
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, warn};

use crate::{
    crypto::{CryptoError, UserKey, decrypt_udp_packet_with_hint, diagnose_udp_packet},
    metrics::{Metrics, Protocol, Transport},
    protocol::parse_target_addr,
    server::nat::{NatKey, NatTable, UdpResponseSender},
    server::replay::{self, ReplayCheck, ReplayStore},
};

use super::super::connect::resolve_udp_target;
use super::super::constants::{
    MAX_UDP_PAYLOAD_SIZE, UDP_CACHED_USER_INDEX_EMPTY, UDP_MAX_CONCURRENT_RELAY_TASKS,
    WS_CTRL_CHANNEL_CAPACITY, WS_DATA_CHANNEL_CAPACITY,
};
use super::super::dns_cache::DnsCache;
use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;

/// Process-wide singletons shared by every UDP relay task.
pub(in crate::server) struct UdpServerCtx {
    pub(in crate::server) metrics: Arc<Metrics>,
    pub(in crate::server) nat_table: Arc<NatTable>,
    pub(in crate::server) replay_store: Arc<ReplayStore>,
    pub(in crate::server) dns_cache: Arc<DnsCache>,
    pub(in crate::server) prefer_ipv4_upstream: bool,
    pub(in crate::server) relay_semaphore: Option<Arc<Semaphore>>,
}

/// Per-path state for a single UDP WebSocket session.
pub(in crate::server) struct UdpRouteCtx {
    pub(in crate::server) users: Arc<[UserKey]>,
    pub(in crate::server) protocol: Protocol,
    pub(in crate::server) path: Arc<str>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
}

/// Per-session mutable state shared across concurrent datagram tasks.
#[derive(Clone)]
struct UdpSessionState {
    session_recorded: Arc<AtomicBool>,
    cached_user_index: Arc<AtomicUsize>,
}

async fn handle_udp_datagram_common<Msg>(
    server: &UdpServerCtx,
    route: &UdpRouteCtx,
    session: &UdpSessionState,
    data: Bytes,
    outbound_tx: mpsc::Sender<Msg>,
    make_response_sender: fn(mpsc::Sender<Msg>, Protocol) -> UdpResponseSender,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let started_at = std::time::Instant::now();
    let preferred_user_index = match session.cached_user_index.load(Ordering::Relaxed) {
        UDP_CACHED_USER_INDEX_EMPTY => None,
        index => Some(index),
    };
    let (packet, user_index) =
        match decrypt_udp_packet_with_hint(route.users.as_ref(), &data, preferred_user_index) {
            Ok(result) => result,
            Err(CryptoError::UnknownUser) => {
                debug!(
                    path = %route.path,
                    candidates = ?route.candidate_users,
                    attempts = ?diagnose_udp_packet(route.users.as_ref(), &data),
                    "udp authentication failed for all path candidates"
                );
                return Err(anyhow!(
                    "no configured key matched the incoming udp data on path {} candidates={:?}",
                    route.path,
                    route.candidate_users,
                ));
            },
            Err(error) => return Err(anyhow!(error)),
        };
    session.cached_user_index.store(user_index, Ordering::Relaxed);
    let user_id = packet.user.id_arc();
    if let Some((csid, pid)) = replay::replay_key(&packet.session, packet.packet_id) {
        match server.replay_store.check_and_mark(csid, pid) {
            ReplayCheck::Fresh => {},
            ReplayCheck::Replay => {
                server
                    .metrics
                    .record_udp_replay_dropped(Arc::clone(&user_id), route.protocol);
                warn!(
                    user = packet.user.id(),
                    path = %route.path,
                    packet_id = pid,
                    "dropping replayed ss-2022 udp datagram"
                );
                return Ok(());
            },
            ReplayCheck::StoreFull => {
                server
                    .metrics
                    .record_udp_replay_store_full_dropped(Arc::clone(&user_id), route.protocol);
                warn!(
                    user = packet.user.id(),
                    path = %route.path,
                    packet_id = pid,
                    "dropping ss-2022 udp datagram: replay store at capacity"
                );
                return Ok(());
            },
        }
    }
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.display_host_port();
    if session.session_recorded.swap(true, Ordering::Relaxed) {
        server.metrics.record_client_last_seen(Arc::clone(&user_id));
    } else {
        server
            .metrics
            .record_client_session(Arc::clone(&user_id), route.protocol, Transport::Udp);
    }
    debug!(
        user = packet.user.id(),
        cipher = packet.user.cipher().as_str(),
        path = %route.path,
        "udp shadowsocks user authenticated"
    );

    let resolved =
        resolve_udp_target(server.dns_cache.as_ref(), &target, server.prefer_ipv4_upstream).await?;
    debug!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        path = %route.path,
        target = %target_display,
        resolved = %resolved,
        "udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: Arc::clone(&user_id),
        fwmark: packet.user.fwmark(),
        target: resolved,
    };
    let entry = server
        .nat_table
        .get_or_create(nat_key, &packet.user, packet.session.clone(), Arc::clone(&server.metrics))
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry
        .register_session(make_response_sender(outbound_tx, route.protocol), packet.session.clone())
        .await;

    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        server.metrics.record_udp_oversized_datagram_dropped(
            Arc::clone(&user_id),
            route.protocol,
            "client_to_target",
        );
        warn!(
            user = packet.user.id(),
            path = %route.path,
            target = %resolved,
            plaintext_bytes = payload.len(),
            max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
            "dropping oversized udp datagram before upstream send"
        );
        server.metrics.record_udp_request(
            Arc::clone(&user_id),
            route.protocol,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Ok(());
    }
    server.metrics.record_udp_payload_bytes(
        Arc::clone(&user_id),
        route.protocol,
        "client_to_target",
        payload.len(),
    );
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        server.metrics.record_udp_request(
            Arc::clone(&user_id),
            route.protocol,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    server.metrics.record_udp_request(
        user_id,
        route.protocol,
        "success",
        started_at.elapsed().as_secs_f64(),
    );

    Ok(())
}

async fn run_udp_relay<T: WsSocket>(
    socket: T,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
) -> Result<()> {
    let (mut reader, writer) = socket.split_io();
    let (outbound_data_tx, outbound_data_rx) = mpsc::channel::<T::Msg>(WS_DATA_CHANNEL_CAPACITY);
    let (outbound_ctrl_tx, outbound_ctrl_rx) = mpsc::channel::<T::Msg>(WS_CTRL_CHANNEL_CAPACITY);
    let session = UdpSessionState {
        session_recorded: Arc::new(AtomicBool::new(false)),
        cached_user_index: Arc::new(AtomicUsize::new(UDP_CACHED_USER_INDEX_EMPTY)),
    };
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    let writer_task = tokio::spawn(ws_writer::run_ws_writer::<T>(
        writer,
        outbound_ctrl_rx,
        outbound_data_rx,
        server.metrics.clone(),
        Transport::Udp,
        route.protocol,
    ));

    let mut loop_result = Ok(());
    loop {
        tokio::select! {
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
            msg = T::recv(&mut reader) => {
                let frame = match msg {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(error) => {
                        loop_result = Err(error);
                        break;
                    }
                };
                match T::classify(frame) {
                    WsFrame::Binary(data) => {
                        server.metrics.record_websocket_binary_frame(Transport::Udp, route.protocol, "in", data.len());
                        if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                            server.metrics.record_udp_relay_drop(Transport::Udp, route.protocol, "concurrency_limit");
                            warn!("udp concurrent relay limit reached, dropping datagram");
                            continue;
                        }
                        // Reserve a slot against the process-wide cap so that
                        // fan-out across WebSocket sessions cannot blow up the
                        // total in-flight task count. Drop the datagram with a
                        // distinct label when the global ceiling is reached.
                        let global_permit = match server.relay_semaphore
                            .as_ref()
                            .map(|sem| Arc::clone(sem).try_acquire_owned())
                        {
                            Some(Ok(permit)) => Some(permit),
                            Some(Err(_)) => {
                                server.metrics.record_udp_relay_drop(
                                    Transport::Udp,
                                    route.protocol,
                                    "global_concurrency_limit",
                                );
                                warn!(
                                    "global udp concurrent relay limit reached, dropping datagram"
                                );
                                continue;
                            }
                            None => None,
                        };
                        let tx = outbound_data_tx.clone();
                        let server = Arc::clone(&server);
                        let route = Arc::clone(&route);
                        let session = session.clone();
                        in_flight.push(async move {
                            if let Err(error) = handle_udp_datagram_common(
                                &server,
                                &route,
                                &session,
                                data,
                                tx,
                                T::make_udp_response_sender,
                            )
                            .await
                            {
                                warn!(?error, "udp datagram relay failed");
                            }
                            // Hold the permit until the relay future completes
                            // so the semaphore accurately reflects in-flight
                            // work; dropping here releases the slot.
                            drop(global_permit);
                        }.boxed());
                    }
                    WsFrame::Close => {
                        debug!("client closed udp websocket");
                        break;
                    }
                    WsFrame::Ping(payload) => {
                        if outbound_ctrl_tx
                            .send(T::pong_msg(payload))
                            .await
                            .is_err()
                        {
                            loop_result = Err(anyhow!("failed to queue websocket pong"));
                            break;
                        }
                    }
                    WsFrame::Pong => {}
                    WsFrame::Text => {
                        loop_result = Err(anyhow!("text websocket frames are not supported"));
                        break;
                    }
                }
            }
        }
    }

    while in_flight.next().await.is_some() {}
    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    writer_task.await.context("websocket writer task join failed")??;
    loop_result
}

pub(super) async fn handle_udp_connection(
    socket: WebSocket,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
) -> Result<()> {
    run_udp_relay::<AxumWs>(AxumWs(socket), server, route).await
}

pub(in crate::server) async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
) -> Result<()> {
    run_udp_relay::<H3Ws>(H3Ws(socket), server, route).await
}
