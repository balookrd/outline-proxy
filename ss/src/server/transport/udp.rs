use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use parking_lot::{Mutex, RwLock};
use sockudo_ws::{Http3 as H3Transport, Stream as H3Stream, WebSocketStream as H3WebSocketStream};
use tokio::sync::{Semaphore, mpsc};
use tracing::{debug, info, warn};

use crate::{
    crypto::{
        CryptoError, SessionKeyCache, UserKey, decrypt_udp_packet_with_hint, diagnose_udp_packet,
    },
    metrics::{Metrics, Protocol, Transport},
    protocol::parse_target_addr,
    server::nat::{NatKey, NatTable, UdpResponseSender},
    server::replay::{self, ReplayCheck, ReplayStore},
};

use super::super::connect::resolve_udp_target;
use super::super::constants::{
    MAX_UDP_PAYLOAD_SIZE, UDP_CACHED_USER_INDEX_EMPTY, UDP_MAX_CONCURRENT_RELAY_TASKS,
    WS_CTRL_CHANNEL_CAPACITY,
};
use super::super::dns_cache::DnsCache;
use super::super::resumption::{
    OrphanRegistry, Parked, ParkedSsUdpStream, ResumeOutcome, SessionId,
};
use super::tcp::ResumeContext;
use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;

/// Process-wide counter that hands out a unique 64-bit identifier to
/// every SS-UDP-over-WS stream. The id is stored on each registered
/// `ActiveSession` so that `detach_session_for_stream` only releases
/// the slot when we are still its owner — no risk of trampling a
/// concurrently-reconnected stream's sender.
static SS_UDP_STREAM_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_ss_udp_stream_id() -> u64 {
    SS_UDP_STREAM_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Process-wide singletons shared by every UDP relay task.
pub(in crate::server) struct UdpServerCtx {
    pub(in crate::server) metrics: Arc<Metrics>,
    pub(in crate::server) nat_table: Arc<NatTable>,
    pub(in crate::server) replay_store: Arc<ReplayStore>,
    pub(in crate::server) dns_cache: Arc<DnsCache>,
    pub(in crate::server) prefer_ipv4_upstream: bool,
    pub(in crate::server) relay_semaphore: Option<Arc<Semaphore>>,
    /// Cross-transport session-resumption registry. No-op when
    /// disabled in config; used by the SS-UDP-over-WS path to park
    /// the set of active NAT keys on disconnect and re-attach them
    /// to a resuming stream.
    pub(in crate::server) orphan_registry: Arc<OrphanRegistry>,
    /// Bounded LRU mapping `(user_index, salt) -> derived AEAD key`. Read on
    /// every UDP datagram before falling back to blake3/HKDF + ring's AES-GCM
    /// key schedule; on a hit, the per-packet derivation collapses into a
    /// hashmap lookup.
    pub(in crate::server) session_key_cache: Arc<SessionKeyCache>,
    /// Per-session bounded mpsc capacity for the NAT-reader → WS-writer
    /// fan-in. Resolved from `tuning.ws_data_channel_capacity` so the
    /// same knob governs both TCP and UDP relay backpressure.
    pub(in crate::server) ws_data_channel_capacity: usize,
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
    /// Stream-unique identifier issued at WS-Upgrade time and used by
    /// the SS-UDP park / resume paths to address NAT entries' sender
    /// slots without trampling a concurrently-reconnected stream.
    stream_id: u64,
    /// NAT keys this stream is the active outbound responder of.
    /// Pushed on every successful `register_session`; drained on
    /// park-on-drop. Wrapped in a `parking_lot::Mutex` since the hot
    /// path is per-datagram and async-await isn't needed.
    nat_keys: Arc<Mutex<Vec<NatKey>>>,
    /// User the stream authenticated as (set once on the first
    /// successful AEAD decrypt). Captured early so park-on-drop can
    /// stash it as the parked entry's owner.
    authenticated_user_id: Arc<RwLock<Option<Arc<str>>>>,
    /// Session ID the client offered for resumption, parsed at
    /// WS-Upgrade. Consumed (`take()`) on the first authenticated
    /// datagram by the resume path; subsequent datagrams see `None`
    /// and skip the resume attempt unconditionally.
    pending_resume_request: Arc<Mutex<Option<SessionId>>>,
    /// Session ID the server minted for this stream (the
    /// `X-Outline-Session` response header value). Used as the
    /// registry key on park.
    issued_session_id: Option<SessionId>,
    /// Set by the first packet that ran (or skipped) the resume
    /// attempt — guards against re-running the lookup on every
    /// concurrent in-flight datagram.
    resume_attempted: Arc<AtomicBool>,
}

/// Tries to attach a parked SS-UDP stream's NAT entries to the new
/// `UdpResponseSender`. Returns the count of NAT keys successfully
/// re-pointed (entries whose TTL hadn't expired in the registry yet).
///
/// Cross-shape mismatches (resume ID minted under TCP / VLESS-UDP /
/// VLESS mux) are reported as a security event and treated as a
/// quiet miss — the next datagram falls through to the normal
/// `get_or_create` flow.
async fn attempt_ss_udp_resume(
    server: &UdpServerCtx,
    session: &UdpSessionState,
    user_id: &Arc<str>,
    udp_session: &crate::crypto::UdpCipherMode,
    sender: &UdpResponseSender,
    path: &str,
) -> usize {
    if !server.orphan_registry.enabled() {
        return 0;
    }
    let resume_id = match session.pending_resume_request.lock().take() {
        Some(id) => id,
        None => return 0,
    };
    let outcome = server.orphan_registry.take_for_resume(resume_id, user_id);
    let parked = match outcome {
        ResumeOutcome::Hit(Parked::SsUdpStream(parked)) => parked,
        ResumeOutcome::Hit(other) => {
            warn!(
                user = %user_id,
                path,
                parked_kind = other.kind(),
                "rejecting ss-udp resume: parked entry is not an ss-udp stream"
            );
            return 0;
        },
        ResumeOutcome::Miss(_) => return 0,
    };
    let mut reattached = 0usize;
    let mut keys_for_self = Vec::with_capacity(parked.nat_keys.len());
    for key in parked.nat_keys {
        match server.nat_table.try_get(&key) {
            Some(entry) => {
                entry
                    .register_session(sender.clone(), udp_session.clone(), session.stream_id)
                    .await;
                keys_for_self.push(key);
                reattached += 1;
            },
            None => {
                debug!(
                    user = %user_id,
                    target = %key.target,
                    "ss-udp resume: parked NAT entry already evicted; skipping"
                );
            },
        }
    }
    if reattached > 0 {
        let mut guard = session.nat_keys.lock();
        for key in keys_for_self {
            if !guard.contains(&key) {
                guard.push(key);
            }
        }
        info!(
            user = %user_id,
            path,
            reattached,
            "ss-udp stream resumed from orphan registry"
        );
    }
    reattached
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
        match decrypt_udp_packet_with_hint(
            route.users.as_ref(),
            &data,
            preferred_user_index,
            Some(server.session_key_cache.as_ref()),
        ) {
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
    // Capture the authenticated user id once. Subsequent datagrams in
    // the same stream skip the write-lock fast-path because the value
    // is already populated.
    if session.authenticated_user_id.read().is_none() {
        let mut guard = session.authenticated_user_id.write();
        if guard.is_none() {
            *guard = Some(Arc::clone(&user_id));
        }
    }
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

    let response_sender = make_response_sender(outbound_tx, route.protocol);

    // First-frame resume: if this stream advertised a pending
    // `X-Outline-Resume` ID, attempt the lookup and re-attach every
    // surviving NAT entry to our response sender before we register
    // the current packet's NAT key. Subsequent packets see
    // `resume_attempted == true` and skip straight to register.
    if !session.resume_attempted.swap(true, Ordering::SeqCst) {
        attempt_ss_udp_resume(
            server,
            session,
            &user_id,
            &packet.session,
            &response_sender,
            &route.path,
        )
        .await;
    }

    entry
        .register_session(
            response_sender,
            packet.session.clone(),
            session.stream_id,
        )
        .await;
    // Track the NAT key as one this stream owns, for park-on-drop.
    {
        let mut guard = session.nat_keys.lock();
        if !guard.contains(&nat_key_for_session(&user_id, packet.user.fwmark(), resolved)) {
            guard.push(NatKey {
                user_id: Arc::clone(&user_id),
                fwmark: packet.user.fwmark(),
                target: resolved,
            });
        }
    }

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
    entry
        .user_counters()
        .udp_in(route.protocol)
        .increment(payload.len() as u64);
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
    resume: ResumeContext,
) -> Result<()> {
    let (mut reader, writer) = socket.split_io();
    let (outbound_data_tx, outbound_data_rx) =
        mpsc::channel::<T::Msg>(server.ws_data_channel_capacity);
    let (outbound_ctrl_tx, outbound_ctrl_rx) = mpsc::channel::<T::Msg>(WS_CTRL_CHANNEL_CAPACITY);
    let session = UdpSessionState {
        session_recorded: Arc::new(AtomicBool::new(false)),
        cached_user_index: Arc::new(AtomicUsize::new(UDP_CACHED_USER_INDEX_EMPTY)),
        stream_id: next_ss_udp_stream_id(),
        nat_keys: Arc::new(Mutex::new(Vec::new())),
        authenticated_user_id: Arc::new(RwLock::new(None)),
        pending_resume_request: Arc::new(Mutex::new(resume.requested_resume)),
        issued_session_id: resume.issued_session_id,
        resume_attempted: Arc::new(AtomicBool::new(false)),
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

    // Park-on-drop: if the stream issued a Session ID and registered
    // at least one NAT key, detach our sender from each entry and
    // park the bundle in the orphan registry. The NAT entries
    // themselves stay alive in `NatTable` and continue aging by
    // their normal idle timeout — only the response-sender slot is
    // released so upstream packets don't try to push to a dead
    // channel.
    park_ss_udp_stream_on_drop(&server, &route, &session).await;

    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    writer_task.await.context("websocket writer task join failed")??;
    loop_result
}

async fn park_ss_udp_stream_on_drop(
    server: &UdpServerCtx,
    route: &UdpRouteCtx,
    session: &UdpSessionState,
) {
    let Some(session_id) = session.issued_session_id else {
        return;
    };
    if !server.orphan_registry.enabled() {
        return;
    }
    let owner = match session.authenticated_user_id.read().clone() {
        Some(owner) => owner,
        None => return, // Stream never authenticated — nothing to park.
    };
    let nat_keys: Vec<NatKey> = std::mem::take(&mut *session.nat_keys.lock());
    if nat_keys.is_empty() {
        return;
    }
    // Detach our sender from each NAT entry. Skips entries where a
    // newer stream has already taken the slot (`stream_id` doesn't
    // match) — they're not ours to clear.
    let mut keys_to_park = Vec::with_capacity(nat_keys.len());
    for key in nat_keys {
        if let Some(entry) = server.nat_table.try_get(&key) {
            let detached = entry.detach_session_for_stream(session.stream_id).await;
            if detached {
                keys_to_park.push(key);
            } else {
                debug!(
                    target = %key.target,
                    "ss-udp park: NAT entry already taken over by another stream; skipping"
                );
            }
        }
    }
    if keys_to_park.is_empty() {
        return;
    }
    debug!(
        user = %owner,
        path = %route.path,
        keys = keys_to_park.len(),
        "parking ss-udp stream into orphan registry"
    );
    server.orphan_registry.park(
        session_id,
        Parked::SsUdpStream(ParkedSsUdpStream {
            nat_keys: keys_to_park,
            owner,
            protocol: route.protocol,
        }),
    );
}

pub(super) async fn handle_udp_connection(
    socket: WebSocket,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
    resume: ResumeContext,
) -> Result<()> {
    run_udp_relay::<AxumWs>(AxumWs(socket), server, route, resume).await
}

pub(in crate::server) async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<UdpServerCtx>,
    route: Arc<UdpRouteCtx>,
    resume: ResumeContext,
) -> Result<()> {
    run_udp_relay::<H3Ws>(H3Ws(socket), server, route, resume).await
}

/// Helper that returns a `NatKey` triple under a single ergonomic
/// call site — saves a few lines in the hot per-datagram path.
fn nat_key_for_session(user_id: &Arc<str>, fwmark: Option<u32>, target: std::net::SocketAddr) -> NatKey {
    NatKey {
        user_id: Arc::clone(user_id),
        fwmark,
        target,
    }
}
