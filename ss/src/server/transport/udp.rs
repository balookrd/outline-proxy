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
    nat::{NatKey, NatTable, UdpResponseSender},
    protocol::parse_target_addr,
};

use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;
use super::super::connect::resolve_udp_target;
use super::super::constants::{
    MAX_UDP_PAYLOAD_SIZE, UDP_CACHED_USER_INDEX_EMPTY, UDP_MAX_CONCURRENT_RELAY_TASKS,
};
use super::super::dns_cache::DnsCache;

#[allow(clippy::too_many_arguments)]
async fn handle_udp_datagram_common<Msg>(
    nat_table: Arc<NatTable>,
    users: Arc<[UserKey]>,
    data: Bytes,
    outbound_tx: mpsc::Sender<Msg>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    udp_session_recorded: Arc<AtomicBool>,
    cached_user_index: Arc<AtomicUsize>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    make_response_sender: fn(mpsc::Sender<Msg>, Protocol) -> UdpResponseSender,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let started_at = std::time::Instant::now();
    let preferred_user_index = match cached_user_index.load(Ordering::Relaxed) {
        UDP_CACHED_USER_INDEX_EMPTY => None,
        index => Some(index),
    };
    let (packet, user_index) = match decrypt_udp_packet_with_hint(
        users.as_ref(),
        &data,
        preferred_user_index,
    ) {
        Ok(result) => result,
        Err(CryptoError::UnknownUser) => {
            debug!(
                path = %path,
                candidates = ?candidate_users,
                attempts = ?diagnose_udp_packet(users.as_ref(), &data),
                "udp authentication failed for all path candidates"
            );
            return Err(anyhow!(
                "no configured key matched the incoming udp data on path {path} candidates={candidate_users:?}",
            ));
        },
        Err(error) => return Err(anyhow!(error)),
    };
    cached_user_index.store(user_index, Ordering::Relaxed);
    let user_id = packet.user.id_arc();
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.display_host_port();
    if udp_session_recorded.swap(true, Ordering::Relaxed) {
        metrics.record_client_last_seen(Arc::clone(&user_id));
    } else {
        metrics.record_client_session(Arc::clone(&user_id), protocol, Transport::Udp);
    }
    debug!(
        user = packet.user.id(),
        cipher = packet.user.cipher().as_str(),
        path = %path,
        "udp shadowsocks user authenticated"
    );

    let resolved = resolve_udp_target(dns_cache.as_ref(), &target, prefer_ipv4_upstream).await?;
    debug!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        path = %path,
        target = %target_display,
        resolved = %resolved,
        "udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: Arc::clone(&user_id),
        fwmark: packet.user.fwmark(),
        target: resolved,
    };
    let entry = nat_table
        .get_or_create(nat_key, &packet.user, packet.session.clone(), Arc::clone(&metrics))
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry
        .register_session(
            make_response_sender(outbound_tx, protocol),
            packet.session.clone(),
        )
        .await;

    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        metrics.record_udp_oversized_datagram_dropped(
            Arc::clone(&user_id),
            protocol,
            "client_to_target",
        );
        warn!(
            user = packet.user.id(),
            path = %path,
            target = %resolved,
            plaintext_bytes = payload.len(),
            max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
            "dropping oversized udp datagram before upstream send"
        );
        metrics.record_udp_request(
            Arc::clone(&user_id),
            protocol,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Ok(());
    }
    metrics.record_udp_payload_bytes(
        Arc::clone(&user_id),
        protocol,
        "client_to_target",
        payload.len(),
    );
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        metrics.record_udp_request(
            Arc::clone(&user_id),
            protocol,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    metrics.record_udp_request(user_id, protocol, "success", started_at.elapsed().as_secs_f64());

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_relay<T: WsSocket>(
    socket: T,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    global_relay_semaphore: Option<Arc<Semaphore>>,
) -> Result<()> {
    let (mut reader, writer) = socket.split_io();
    let (outbound_data_tx, outbound_data_rx) = mpsc::channel::<T::Msg>(64);
    let (outbound_ctrl_tx, outbound_ctrl_rx) = mpsc::channel::<T::Msg>(8);
    let udp_session_recorded = Arc::new(AtomicBool::new(false));
    let cached_user_index = Arc::new(AtomicUsize::new(UDP_CACHED_USER_INDEX_EMPTY));
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    let writer_task = tokio::spawn(ws_writer::run_ws_writer::<T>(
        writer,
        outbound_ctrl_rx,
        outbound_data_rx,
        metrics.clone(),
        Transport::Udp,
        protocol,
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
                        metrics.record_websocket_binary_frame(Transport::Udp, protocol, "in", data.len());
                        if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                            metrics.record_udp_relay_drop(Transport::Udp, protocol, "concurrency_limit");
                            warn!("udp concurrent relay limit reached, dropping datagram");
                            continue;
                        }
                        // Reserve a slot against the process-wide cap so that
                        // fan-out across WebSocket sessions cannot blow up the
                        // total in-flight task count. Drop the datagram with a
                        // distinct label when the global ceiling is reached.
                        let global_permit = match global_relay_semaphore
                            .as_ref()
                            .map(|sem| Arc::clone(sem).try_acquire_owned())
                        {
                            Some(Ok(permit)) => Some(permit),
                            Some(Err(_)) => {
                                metrics.record_udp_relay_drop(
                                    Transport::Udp,
                                    protocol,
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
                        let users = users.clone();
                        let metrics = metrics.clone();
                        let path = path.clone();
                        let candidate_users = candidate_users.clone();
                        let udp_session_recorded = udp_session_recorded.clone();
                        let cached_user_index = Arc::clone(&cached_user_index);
                        let nat_table = Arc::clone(&nat_table);
                        let dns_cache = Arc::clone(&dns_cache);
                        in_flight.push(async move {
                            if let Err(error) = handle_udp_datagram_common(
                                nat_table,
                                users,
                                data,
                                tx,
                                metrics,
                                protocol,
                                path,
                                candidate_users,
                                udp_session_recorded,
                                cached_user_index,
                                dns_cache,
                                prefer_ipv4_upstream,
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_udp_connection(
    socket: WebSocket,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    global_relay_semaphore: Option<Arc<Semaphore>>,
) -> Result<()> {
    run_udp_relay::<AxumWs>(
        AxumWs(socket),
        users,
        metrics,
        protocol,
        path,
        candidate_users,
        nat_table,
        dns_cache,
        prefer_ipv4_upstream,
        global_relay_semaphore,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(in crate::server) async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
    global_relay_semaphore: Option<Arc<Semaphore>>,
) -> Result<()> {
    run_udp_relay::<H3Ws>(
        H3Ws(socket),
        users,
        metrics,
        Protocol::Http3,
        path,
        candidate_users,
        nat_table,
        dns_cache,
        prefer_ipv4_upstream,
        global_relay_semaphore,
    )
    .await
}
