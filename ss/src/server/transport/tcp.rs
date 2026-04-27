use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use sockudo_ws::{Http3 as H3Transport, Stream as H3Stream, WebSocketStream as H3WebSocketStream};
use std::time::Duration;

use tokio::{
    io::AsyncWriteExt,
    sync::{Notify, mpsc},
};
use tracing::{debug, info, warn};

/// Failure modes returned by [`handle_tcp_binary_frame`]. [`run_tcp_relay`]
/// matches on this to decide whether to send the client a "try again" close
/// frame (RFC 6455 code 1013) — so the client can retry on the same or a
/// different uplink — or a plain close for terminal errors (auth, protocol).
enum FrameError {
    UpstreamConnectFailed(anyhow::Error),
    Fatal(anyhow::Error),
}

impl FrameError {
    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::UpstreamConnectFailed(e) | Self::Fatal(e) => e,
        }
    }
}

impl From<anyhow::Error> for FrameError {
    fn from(e: anyhow::Error) -> Self {
        Self::Fatal(e)
    }
}

use crate::{
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, UserKey,
        diagnose_stream_handshake,
    },
    metrics::{Metrics, PerUserCounters, Protocol, TcpUpstreamGuard, Transport},
    outbound::OutboundIpv6,
    protocol::parse_target_addr,
};

use super::super::connect::connect_tcp_target;
use super::super::relay::UpstreamRelayOutcome;
use super::super::resumption::{
    OrphanRegistry, Parked, ParkedTcp, ResumeOutcome, SessionId, TcpProtocolContext,
};
use super::super::constants::{
    WS_CTRL_CHANNEL_CAPACITY, WS_PONG_DEADLINE_MULTIPLIER, WS_TCP_KEEPALIVE_PING_INTERVAL_SECS,
};
use super::super::dns_cache::DnsCache;
use super::super::scratch::ScratchBuf;
use super::sink;
use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;

/// Process-wide services shared by every TCP relay session.
pub(in crate::server) struct WsTcpServerCtx {
    pub(in crate::server) metrics: Arc<Metrics>,
    pub(in crate::server) dns_cache: Arc<DnsCache>,
    pub(in crate::server) prefer_ipv4_upstream: bool,
    pub(in crate::server) outbound_ipv6: Option<Arc<OutboundIpv6>>,
    /// Cross-transport session-resumption registry. Always present;
    /// when resumption is disabled in config the registry is a no-op
    /// and adds no overhead to the TCP path.
    pub(in crate::server) orphan_registry: Arc<OrphanRegistry>,
    /// Per-session bounded mpsc capacity for the upstream-reader →
    /// WS-writer fan-in. Resolved from `tuning.ws_data_channel_capacity`
    /// so deployments can trade memory for video throughput headroom
    /// without code changes.
    pub(in crate::server) ws_data_channel_capacity: usize,
}

/// Per-path state for a single TCP WebSocket session.
pub(in crate::server) struct WsTcpRouteCtx {
    pub(in crate::server) users: Arc<[UserKey]>,
    pub(in crate::server) protocol: Protocol,
    pub(in crate::server) path: Arc<str>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
}

/// Per-request resumption negotiation state, parsed once at WS Upgrade
/// time from `X-Outline-*` headers and threaded into the relay loop.
#[derive(Default)]
pub(in crate::server) struct ResumeContext {
    /// Session ID the client asked us to resume. Validated against the
    /// orphan registry only after authentication succeeds, since the
    /// upgrade handler does not know `user_id` yet.
    pub(in crate::server) requested_resume: Option<SessionId>,
    /// Session ID we minted (and surfaced to the client via the
    /// `X-Outline-Session` response header) so that, on disconnect, the
    /// upstream can be parked under a key the client already knows.
    pub(in crate::server) issued_session_id: Option<SessionId>,
}

/// Lower-cased name of the request header carrying the Session ID a
/// client wishes to resume.
pub(in crate::server) const RESUME_REQUEST_HEADER: &str = "x-outline-resume";
/// Lower-cased name of the request header advertising client support for
/// session resumption.
pub(in crate::server) const RESUME_CAPABLE_HEADER: &str = "x-outline-resume-capable";
/// Lower-cased name of the response header carrying the Session ID the
/// server has assigned to the just-established session.
pub(in crate::server) const SESSION_RESPONSE_HEADER: &str = "x-outline-session";

impl ResumeContext {
    /// Builds a [`ResumeContext`] by inspecting incoming HTTP request
    /// headers and, when applicable, minting a fresh server-issued
    /// Session ID. When resumption is disabled in config — or when the
    /// client neither offered `Resume` nor advertised `Resume-Capable` —
    /// both fields are left `None` and the relay path runs unchanged.
    pub(in crate::server) fn from_request_headers(
        headers: &axum::http::HeaderMap,
        registry: &OrphanRegistry,
    ) -> Self {
        let requested_resume = headers
            .get(RESUME_REQUEST_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(SessionId::parse_hex);
        let resume_capable = headers
            .get(RESUME_CAPABLE_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == "1");
        let issued_session_id = if registry.enabled()
            && (resume_capable || requested_resume.is_some())
        {
            registry.mint_session_id()
        } else {
            None
        };
        Self { requested_resume, issued_session_id }
    }

    /// Inserts the `X-Outline-Session` response header carrying the
    /// minted Session ID. No-op when no ID was minted.
    pub(in crate::server) fn issue_session_header(&self, headers: &mut axum::http::HeaderMap) {
        if let Some(id) = self.issued_session_id
            && let Ok(value) = axum::http::HeaderValue::from_str(&id.to_hex())
        {
            headers.insert(SESSION_RESPONSE_HEADER, value);
        }
    }
}

/// Relay-task return type used by the TCP-WS path. Carries either a
/// closed outcome (no parking possible) or the harvested reader half so
/// that [`run_tcp_relay`] can park it after the client disconnects.
type RelayTaskOutput = Result<UpstreamRelayOutcome<tokio::net::tcp::OwnedReadHalf>>;

struct WsTcpRelayState {
    upstream_writer: Option<tokio::net::tcp::OwnedWriteHalf>,
    upstream_to_client: Option<tokio::task::JoinHandle<RelayTaskOutput>>,
    /// Notify used to ask the spawned relay task to stop and return its
    /// reader half. Set in tandem with `upstream_to_client`.
    relay_cancel: Option<Arc<Notify>>,
    authenticated_user: Option<UserKey>,
    user_counters: Option<Arc<PerUserCounters>>,
    upstream_guard: Option<TcpUpstreamGuard>,
    /// Human-readable target host:port for the active upstream. Only used
    /// for park-time logging and to populate `ParkedTcp::target_display`.
    upstream_target_display: Option<Arc<str>>,
    /// Mirror of [`ResumeContext::issued_session_id`] kept on the relay
    /// state so the park-on-drop branch can find it without re-threading
    /// `ResumeContext` through every helper.
    issued_session_id: Option<SessionId>,
    /// Session ID the client asked us to resume. Consumed (`take()`) at
    /// the first authenticated frame; on resume hit it points at parked
    /// state, on miss it is dropped and a fresh upstream is established.
    pending_resume_request: Option<SessionId>,
}

struct WsTcpFrameOutput<'a, Msg> {
    data_tx: &'a mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
}

impl WsTcpRelayState {
    fn new(resume: ResumeContext) -> Self {
        Self {
            upstream_writer: None,
            upstream_to_client: None,
            relay_cancel: None,
            authenticated_user: None,
            user_counters: None,
            upstream_guard: None,
            upstream_target_display: None,
            issued_session_id: resume.issued_session_id,
            pending_resume_request: resume.requested_resume,
        }
    }
}

struct ChannelSink<Msg: Send + 'static> {
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
}

impl<Msg: Send + 'static> super::super::relay::UpstreamSink for ChannelSink<Msg> {
    async fn send_ciphertext(&mut self, ciphertext: Bytes) -> Result<()> {
        self.tx
            .send((self.make_binary)(ciphertext))
            .await
            .map_err(|error| anyhow!("failed to queue encrypted websocket frame: {error}"))
    }

    async fn close(&mut self) {
        let _ = self.tx.send((self.make_close)()).await;
    }
}

async fn run_tcp_relay<T: WsSocket>(
    socket: T,
    server: &WsTcpServerCtx,
    route: &WsTcpRouteCtx,
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

    let mut decryptor = AeadStreamDecryptor::new(route.users.clone());
    let mut plaintext_buffer = ScratchBuf::take();
    let mut state = WsTcpRelayState::new(resume);
    let mut client_closed = false;

    // Periodic WebSocket Ping sent from server to client.
    //
    // The client's WsReadTransport has a WS_READ_IDLE_TIMEOUT (currently 300 s)
    // that fires when no WS frame has been received.  On a healthy session where
    // the remote target is slow to respond (e.g. a long model-inference step),
    // that timer would fire and abort an otherwise live connection.
    //
    // Sending a Ping every WS_TCP_KEEPALIVE_PING_INTERVAL_SECS seconds keeps
    // the client's timer reset for as long as the session is alive, regardless
    // of how long the remote target takes.  The client's WsReadTransport already
    // handles incoming Pings: it queues a Pong response and loops — every Ping
    // frame also resets the idle timeout.
    let ping_interval = Duration::from_secs(WS_TCP_KEEPALIVE_PING_INTERVAL_SECS);
    let pong_deadline = ping_interval * WS_PONG_DEADLINE_MULTIPLIER;
    let mut keepalive = tokio::time::interval(ping_interval);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await; // skip the first immediate tick
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
                        if let Err(frame_err) = handle_tcp_binary_frame(
                            &mut state,
                            &mut decryptor,
                            &mut plaintext_buffer,
                            data,
                            server,
                            route,
                            WsTcpFrameOutput {
                                data_tx: &outbound_data_tx,
                                make_binary: T::binary_msg,
                                make_close: T::close_msg,
                            },
                        )
                        .await
                        {
                            // Pick the appropriate WS close code.  When the upstream
                            // TCP connect failed the client has a reasonable chance of
                            // succeeding if it retries (same or different uplink), so
                            // send code 1013 "Try Again Later".  Any other error
                            // (auth failure, protocol error) is terminal — send a
                            // generic close so the client can fail fast.
                            //
                            // For Fatal failures we also drain inbound traffic to
                            // /dev/null until the handshake-equivalent timeout (or
                            // the byte cap) before closing.  Without the sink an
                            // active probe could fingerprint SS by timing the close
                            // against the AEAD-block boundary; sinking matches the
                            // VLESS path and a stalled-handshake response shape.
                            let (close_msg, sinked) = match &frame_err {
                                FrameError::UpstreamConnectFailed(_) => {
                                    (T::close_try_again_msg(), false)
                                },
                                FrameError::Fatal(_) => {
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
                        debug!("client closed tcp websocket");
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
                // Tear down silently-dead sessions: if no inbound frame has
                // been seen for `pong_deadline`, the peer is gone (mobile in
                // tunnel, NAT rebind, ISP black-hole). Without this check we
                // wait on the underlying TCP/QUIC keepalive, which can be
                // minutes — long enough to pin upstream sockets and buffers.
                if last_inbound.elapsed() > pong_deadline {
                    debug!(
                        elapsed_secs = last_inbound.elapsed().as_secs(),
                        "tcp websocket pong deadline exceeded; closing session"
                    );
                    break;
                }
                // Don't fail the session on a Ping send error — the writer task
                // may have already exited if the WS connection closed cleanly on
                // the write side while we were reading.  The next T::recv() call
                // will then return None and we exit normally.
                let _ = outbound_ctrl_tx.send(T::ping_msg()).await;
            }
        }
    }

    // Try to park the upstream into the orphan registry before any
    // teardown. `try_park_on_drop` consumes the relevant fields of `state`
    // on success; on failure it leaves them intact for the legacy cleanup
    // below.
    let parked = try_park_on_drop(&mut state, server, route).await;

    if !parked {
        if let Some(mut upstream) = state.upstream_writer.take() {
            upstream.shutdown().await.ok();
        }
        if client_closed {
            if let Some(task) = state.upstream_to_client.take() {
                task.abort();
            }
        } else if let Some(task) = state.upstream_to_client.take() {
            // Surface relay-task errors but ignore the resumption outcome
            // (we already decided not to park).
            match task.await.context("tcp upstream relay task join failed")? {
                Ok(_) => {},
                Err(error) => return Err(error),
            }
        }
        if let Some(guard) = state.upstream_guard.take() {
            guard.finish();
        }
    }

    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    if client_closed || parked {
        let _ = writer_task.await;
    } else {
        writer_task.await.context("websocket writer task join failed")??;
    }
    Ok(())
}

/// Attempts to move the still-live upstream socket into the orphan
/// registry. Returns `true` iff the upstream was parked; on `false` the
/// caller falls back to legacy shutdown.
///
/// All early-exit paths leave `state.upstream_writer` (and friends)
/// intact so the legacy cleanup branch can take over without surprise.
async fn try_park_on_drop(
    state: &mut WsTcpRelayState,
    server: &WsTcpServerCtx,
    route: &WsTcpRouteCtx,
) -> bool {
    if !server.orphan_registry.enabled() {
        return false;
    }
    let Some(session_id) = state.issued_session_id else {
        return false;
    };
    if state.upstream_writer.is_none() {
        // Authentication never completed (or upstream connect failed).
        return false;
    }
    // Harvest the spawned relay task's reader half via cancel-notify.
    let Some(cancel) = state.relay_cancel.take() else {
        return false;
    };
    let Some(task) = state.upstream_to_client.take() else {
        return false;
    };
    cancel.notify_one();
    let reader = match task.await {
        Ok(Ok(UpstreamRelayOutcome::Cancelled(reader))) => reader,
        Ok(Ok(UpstreamRelayOutcome::Closed)) => {
            // Upstream EOF'd before our cancel was observed; nothing
            // worth parking.
            return false;
        },
        Ok(Err(error)) => {
            debug!(?error, "relay task errored before park; not parking");
            return false;
        },
        Err(join_error) => {
            warn!(?join_error, "relay task panicked while harvesting reader for park");
            return false;
        },
    };
    let writer = state.upstream_writer.take().expect("checked above");
    let user = match state.authenticated_user.take() {
        Some(user) => user,
        None => {
            // Should not happen if `upstream_writer` was set, but keep
            // the cleanup honest.
            return false;
        },
    };
    let user_counters = match state.user_counters.take() {
        Some(c) => c,
        None => return false,
    };
    let upstream_guard = match state.upstream_guard.take() {
        Some(g) => g,
        None => return false,
    };
    let target_display = state
        .upstream_target_display
        .take()
        .unwrap_or_else(|| Arc::from("?"));
    let owner = user.id_arc();
    let parked = ParkedTcp {
        upstream_writer: writer,
        upstream_reader: reader,
        target_display,
        protocol: route.protocol,
        owner: Arc::clone(&owner),
        protocol_context: TcpProtocolContext::Ss(user),
        user_counters,
        upstream_guard,
    };
    debug!(
        user = %owner,
        path = %route.path,
        "parking tcp upstream into orphan registry",
    );
    server.orphan_registry.park(session_id, Parked::Tcp(parked));
    true
}

async fn handle_tcp_binary_frame<Msg>(
    state: &mut WsTcpRelayState,
    decryptor: &mut AeadStreamDecryptor,
    plaintext_buffer: &mut Vec<u8>,
    data: Bytes,
    server: &WsTcpServerCtx,
    route: &WsTcpRouteCtx,
    outbound: WsTcpFrameOutput<'_, Msg>,
) -> Result<(), FrameError>
where
    Msg: Send + 'static,
{
    server
        .metrics
        .record_websocket_binary_frame(Transport::Tcp, route.protocol, "in", data.len());
    decryptor.feed_ciphertext(&data);
    match decryptor.drain_plaintext(plaintext_buffer) {
        Ok(()) => {},
        Err(CryptoError::UnknownUser) => {
            debug!(
                path = %route.path,
                candidates = ?route.candidate_users,
                buffered = decryptor.buffered_data().len(),
                attempts = ?diagnose_stream_handshake(route.users.as_ref(), decryptor.buffered_data()),
                "tcp authentication failed for all path candidates"
            );
            return Err(FrameError::Fatal(anyhow!(
                "no configured key matched the incoming data on tcp path {} candidates={:?}",
                route.path,
                route.candidate_users,
            )));
        },
        Err(error) => return Err(FrameError::Fatal(anyhow!(error))),
    }

    if state.upstream_writer.is_none() {
        let Some((target, consumed)) =
            parse_target_addr(plaintext_buffer).map_err(|e| FrameError::Fatal(anyhow!(e)))?
        else {
            return Ok(());
        };
        let Some(user) = decryptor.user().cloned() else {
            return Ok(());
        };
        debug!(
            user = user.id(),
            cipher = user.cipher().as_str(),
            path = %route.path,
            "tcp shadowsocks user authenticated"
        );
        let user_id = user.id_arc();
        let target_display: Arc<str> = Arc::from(target.display_host_port());

        // Resume attempt: if the client offered a Session ID and the
        // registry has a parked TCP entry for this authenticated user,
        // re-attach to that upstream instead of connecting afresh. The
        // target sent in this handshake is intentionally ignored on a
        // hit — by spec the parked target is authoritative.
        if let Some(resume_id) = state.pending_resume_request.take()
            && let ResumeOutcome::Hit(Parked::Tcp(parked)) =
                server.orphan_registry.take_for_resume(resume_id, &user_id)
        {
            // Cross-protocol mismatch (a SS-authenticated client
            // presents a Session ID minted under VLESS, or vice versa)
            // is rejected outright. The owner check inside
            // `take_for_resume` already binds an ID to a single user
            // identity, so this should only fire if SS and VLESS users
            // share an identifier — a configuration error worth
            // surfacing rather than silently re-routing.
            let TcpProtocolContext::Ss(parked_user) = parked.protocol_context else {
                warn!(
                    user = user.id(),
                    path = %route.path,
                    parked_kind = parked.protocol_context.label(),
                    "rejecting resume: parked session belongs to a different proxy protocol"
                );
                return Err(FrameError::Fatal(anyhow!(
                    "cross-protocol resume rejected: parked session is not SS"
                )));
            };
            info!(
                user = user.id(),
                path = %route.path,
                target = %parked.target_display,
                "tcp upstream resumed from orphan registry"
            );
            let mut encryptor =
                AeadStreamEncryptor::new(&parked_user, decryptor.response_context())
                    .map_err(|e| FrameError::Fatal(anyhow!(e)))?;
            let tx = outbound.data_tx.clone();
            let make_binary = outbound.make_binary;
            let make_close = outbound.make_close;
            let relay_metrics = Arc::clone(&server.metrics);
            let relay_user_id = Arc::clone(&user_id);
            let protocol = route.protocol;
            let cancel = Arc::new(Notify::new());
            let cancel_for_task = Arc::clone(&cancel);
            let parked_reader = parked.upstream_reader;
            state.upstream_to_client = Some(tokio::spawn(async move {
                super::super::relay::relay_upstream_to_client(
                    parked_reader,
                    ChannelSink { tx, make_binary, make_close },
                    &mut encryptor,
                    relay_metrics,
                    protocol,
                    relay_user_id,
                    Some(cancel_for_task),
                )
                .await
            }));
            state.relay_cancel = Some(cancel);
            state.user_counters = Some(parked.user_counters);
            state.authenticated_user = Some(parked_user);
            state.upstream_writer = Some(parked.upstream_writer);
            state.upstream_guard = Some(parked.upstream_guard);
            state.upstream_target_display = Some(parked.target_display);
            plaintext_buffer.drain(..consumed);
            // Subsequent payload bytes (if any) are forwarded by the
            // generic write branch below.
            return forward_plaintext_to_writer(state, plaintext_buffer, route.protocol).await;
        }
        // Fall through: either no resume requested or the registry
        // missed (unknown / owner-mismatch / disabled). The miss is
        // already counted by `take_for_resume`.

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
                    Arc::clone(&user_id),
                    route.protocol,
                    "success",
                    connect_started.elapsed().as_secs_f64(),
                );
                stream
            },
            Err(error) => {
                server.metrics.record_tcp_connect(
                    Arc::clone(&user_id),
                    route.protocol,
                    "error",
                    connect_started.elapsed().as_secs_f64(),
                );
                warn!(
                    user = user.id(),
                    protocol = ?route.protocol,
                    path = %route.path,
                    target = %target_display,
                    error = %error,
                    "websocket tcp upstream connect failed; sending try-again close to client"
                );
                let connect_err = anyhow::Error::msg(format!("{error:#}"))
                    .context(format!("failed to connect to {target_display}"))
                    .context("upstream tcp connect failed");
                return Err(FrameError::UpstreamConnectFailed(connect_err));
            },
        };
        debug!(
            user = user.id(),
            fwmark = ?user.fwmark(),
            path = %route.path,
            target = %target_display,
            "tcp upstream connected"
        );

        let (upstream_reader, writer) = stream.into_split();
        let mut encryptor = AeadStreamEncryptor::new(&user, decryptor.response_context())
            .map_err(|e| FrameError::Fatal(anyhow!(e)))?;
        let tx = outbound.data_tx.clone();
        let make_binary = outbound.make_binary;
        let make_close = outbound.make_close;
        let relay_metrics = Arc::clone(&server.metrics);
        let relay_user_id = Arc::clone(&user_id);
        let protocol = route.protocol;
        // Cancel-notify is registered unconditionally so park-on-drop
        // can harvest the reader. When resumption is disabled the
        // notify is simply never fired and the relay loop runs in its
        // legacy single-arm mode.
        let cancel = Arc::new(Notify::new());
        let cancel_for_task = Arc::clone(&cancel);
        state.upstream_to_client = Some(tokio::spawn(async move {
            super::super::relay::relay_upstream_to_client(
                upstream_reader,
                ChannelSink { tx, make_binary, make_close },
                &mut encryptor,
                relay_metrics,
                protocol,
                relay_user_id,
                Some(cancel_for_task),
            )
            .await
        }));
        state.relay_cancel = Some(cancel);
        server
            .metrics
            .record_tcp_authenticated_session(Arc::clone(&user_id), route.protocol);
        state.upstream_guard =
            Some(server.metrics.open_tcp_upstream_connection(user_id, route.protocol));
        state.user_counters = Some(server.metrics.user_counters(&user.id_arc()));
        state.authenticated_user = Some(user);
        state.upstream_writer = Some(writer);
        state.upstream_target_display = Some(target_display);
        plaintext_buffer.drain(..consumed);
    }

    forward_plaintext_to_writer(state, plaintext_buffer, route.protocol).await
}

/// Forwards any decrypted payload waiting in `plaintext_buffer` to the
/// active upstream writer. Returns `Ok(())` if there is nothing to write
/// or the write succeeded; otherwise wraps the error in `FrameError::Fatal`.
async fn forward_plaintext_to_writer(
    state: &mut WsTcpRelayState,
    plaintext_buffer: &mut Vec<u8>,
    protocol: Protocol,
) -> Result<(), FrameError> {
    if let Some(writer) = &mut state.upstream_writer
        && !plaintext_buffer.is_empty()
    {
        if let Some(counters) = &state.user_counters {
            counters.tcp_in(protocol).increment(plaintext_buffer.len() as u64);
        }
        writer
            .write_all(plaintext_buffer)
            .await
            .context("failed to write decrypted data upstream")
            .map_err(FrameError::Fatal)?;
        plaintext_buffer.clear();
    }
    Ok(())
}

pub(super) async fn handle_tcp_connection(
    socket: WebSocket,
    server: Arc<WsTcpServerCtx>,
    route: WsTcpRouteCtx,
    resume: ResumeContext,
) -> Result<()> {
    run_tcp_relay::<AxumWs>(AxumWs(socket), &server, &route, resume).await
}

pub(in crate::server) async fn handle_tcp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<WsTcpServerCtx>,
    route: WsTcpRouteCtx,
    resume: ResumeContext,
) -> Result<()> {
    run_tcp_relay::<H3Ws>(H3Ws(socket), &server, &route, resume).await
}
