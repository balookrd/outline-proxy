use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, UserKey, diagnose_stream_handshake,
    },
    metrics::{AppProtocol, Metrics, PerUserCounters, Protocol, TcpUpstreamGuard, Transport},
    outbound::OutboundIpv6,
    protocol::parse_target_addr,
};

use super::super::connect::connect_tcp_target;
use super::super::constants::{
    WS_CTRL_CHANNEL_CAPACITY, WS_PONG_DEADLINE_MULTIPLIER, WS_TCP_KEEPALIVE_PING_INTERVAL_SECS,
};
use super::super::dns_cache::DnsCache;
use super::super::relay::UpstreamRelayOutcome;
use super::super::resumption::{
    OrphanRegistry, Parked, ParkedTcp, ResumeOutcome, SessionId, TcpProtocolContext, ack_prefix,
};
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
    /// Per-route LRU consulted at handshake time to skip linear AEAD probing
    /// when the same `peer_addr` previously authenticated against a known
    /// user. Cloned from [`crate::server::state::TransportRoute`] so all
    /// connections on the path share one cache.
    pub(in crate::server) peer_user_cache: Arc<crate::server::peer_user_cache::PeerUserCache>,
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
    /// Whether the client advertised the Ack-Prefix Protocol capability
    /// (`X-Outline-Resume-Ack-Prefix: 1`). When true on a successful
    /// resume hit the server emits a 14-byte control frame ahead of the
    /// upstream→client relay so the client can replay only the bytes
    /// the upstream `TcpStream` has not yet acked.
    /// See `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1).
    pub(in crate::server) ack_prefix_requested: bool,
    /// Whether the client advertised the Symmetric Downlink Replay
    /// (v2) capability (`X-Outline-Resume-Symmetric-Replay: 1`). Per
    /// spec, v2 cannot be active without v1, and the server side must
    /// also have a non-zero `downlink_buffer_bytes`; both gates are
    /// applied at parse time, so a `true` value here already implies
    /// `ack_prefix_requested == true` AND the registry has v2 capacity
    /// configured. See `docs/SESSION-RESUMPTION.md` § Symmetric
    /// Downlink Replay (v2).
    pub(in crate::server) symmetric_replay_requested: bool,
    /// Client-reported `X-Outline-Resume-Down-Acked` offset on a v2
    /// resume request. Counts plaintext downstream bytes the client
    /// has successfully forwarded to its SOCKS5 client over the
    /// session lifetime. Defaults to `0` when:
    ///
    /// - the request is not a resume request,
    /// - v2 capability is not requested,
    /// - the header is absent, or
    /// - the header is malformed (per spec the server treats malformed
    ///   as `0` and proceeds — equivalent to "replay everything still
    ///   in the ring").
    pub(in crate::server) client_acked_offset: u64,
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
/// Lower-cased name of the request **and** response header used to
/// negotiate the Ack-Prefix Protocol (v1). Client sets `1` to advertise
/// support; server echoes `1` to confirm support. See
/// `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1).
pub(in crate::server) const ACK_PREFIX_HEADER: &str = "x-outline-resume-ack-prefix";
/// Lower-cased name of the request **and** response header used to
/// negotiate the Symmetric Downlink Replay (v2) capability. Client
/// sets `1` to advertise support; server echoes `1` to confirm — but
/// only when v1 was also negotiated AND server-side
/// `downlink_buffer_bytes > 0`. See `docs/SESSION-RESUMPTION.md`
/// § Symmetric Downlink Replay (v2).
pub(in crate::server) const SYMMETRIC_REPLAY_HEADER: &str = "x-outline-resume-symmetric-replay";
/// Lower-cased name of the request-only header carrying the client's
/// last-acked downstream offset for v2 resume hits. Decimal `u64`,
/// max `2^63 − 1`; absent or malformed values are treated as `0` per
/// spec. See `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay
/// (v2).
pub(in crate::server) const DOWN_ACKED_HEADER: &str = "x-outline-resume-down-acked";

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
        let issued_session_id =
            if registry.enabled() && (resume_capable || requested_resume.is_some()) {
                registry.mint_session_id()
            } else {
                None
            };
        // Ack-Prefix Protocol capability advertisement. Pre-auth header
        // read is safe: only the boolean capability bit is exposed, no
        // session-id existence is leaked. The actual control-frame emit
        // gates on the post-auth orphan-take hit + this flag.
        let ack_prefix_requested = registry.enabled()
            && headers
                .get(ACK_PREFIX_HEADER)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim() == "1");
        // v2 Symmetric Downlink Replay capability. Per spec, v2 cannot
        // exist without v1, and the server side must have a non-zero
        // `downlink_buffer_bytes` to participate. Both gates are
        // applied here so downstream code can trust a `true` flag
        // unconditionally.
        let symmetric_replay_requested = ack_prefix_requested
            && registry.symmetric_replay_enabled()
            && headers
                .get(SYMMETRIC_REPLAY_HEADER)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.trim() == "1");
        // Client-reported downstream-ack offset. Only meaningful on a
        // resume request that also advertises v2; all other paths see
        // `0`. Per spec a malformed value is treated as `0` (replay
        // everything still in the server's ring) — we log at debug to
        // avoid a noisy WARN on a header an old proxy might forward
        // unfiltered, but the parse failure is observable.
        let client_acked_offset = if symmetric_replay_requested && requested_resume.is_some() {
            match headers
                .get(DOWN_ACKED_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim())
            {
                Some(value) if !value.is_empty() => match value.parse::<u64>() {
                    Ok(n) => n,
                    Err(error) => {
                        debug!(
                            ?error,
                            value,
                            "malformed X-Outline-Resume-Down-Acked; \
                             treating as 0 per spec",
                        );
                        0
                    },
                },
                _ => 0,
            }
        } else {
            0
        };
        Self {
            requested_resume,
            issued_session_id,
            ack_prefix_requested,
            symmetric_replay_requested,
            client_acked_offset,
        }
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
    /// Becomes true after the first successful AEAD decrypt has populated
    /// `route.peer_user_cache` for this `peer_addr`. Subsequent frames skip
    /// the cache write to avoid hammering the LRU mutex on every binary
    /// frame of an established session.
    peer_user_cache_recorded: bool,
    /// Whether the client advertised the Ack-Prefix Protocol capability
    /// in its upgrade request. Mirrored from
    /// [`ResumeContext::ack_prefix_requested`] so the relay loop can
    /// decide whether to emit the control frame on a resume hit without
    /// re-threading `ResumeContext` through every helper.
    ack_prefix_requested: bool,
    /// Whether the client advertised the v2 Symmetric Downlink Replay
    /// capability AND the server has v2 enabled. When true on a
    /// resume hit the relay loop emits the v2 `"ORDR"` frame
    /// immediately after the v1 `"ORSM"` frame. Implies
    /// `ack_prefix_requested == true` (gate enforced at parse time).
    symmetric_replay_requested: bool,
    /// Client-reported `X-Outline-Resume-Down-Acked` offset from the
    /// request side. Used by the resume-emit path to compute
    /// `replay_from(offset)` against the parked downlink ring. `0`
    /// when no v2 negotiation occurred or the request did not carry
    /// the header.
    client_acked_offset_request: u64,
    /// Cumulative bytes the relay has successfully written upstream over
    /// the lifetime of this session. Monotonic; survives parks (the
    /// `Arc<AtomicU64>` is moved into `ParkedTcp` and back on resume).
    /// Read by the Ack-Prefix control frame on resume hit so the client
    /// can replay only the bytes the upstream `TcpStream` has not yet
    /// acked. Counts plaintext payload bytes (post-AEAD-decrypt for
    /// SS-WS; raw VLESS payload for VLESS-WS) — same units the client
    /// tracks on its sent counter.
    upstream_bytes_acked: Arc<AtomicU64>,
    /// Per-session bounded ring buffer for the v2 Symmetric Downlink
    /// Replay protocol. Allocated lazily at upstream-handshake time
    /// when [`Self::symmetric_replay_requested`] is `true` (v2
    /// negotiated and server-side enabled). The relay loop pushes
    /// every plaintext chunk into the ring before encryption; on
    /// park the same `Arc` is moved into [`ParkedTcp::downlink_ring`]
    /// and back on resume hit. `None` means v2 is not engaged on
    /// this session and the ring is never allocated.
    downlink_ring:
        Option<Arc<parking_lot::Mutex<crate::server::resumption::downlink_ring::DownlinkRing>>>,
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
            peer_user_cache_recorded: false,
            ack_prefix_requested: resume.ack_prefix_requested,
            symmetric_replay_requested: resume.symmetric_replay_requested,
            client_acked_offset_request: resume.client_acked_offset,
            // Counter starts at 0 on every fresh session. On resume hit
            // the parked state's Arc replaces this one — see the resume
            // branch in `attach_resumed_state_or_dial`.
            upstream_bytes_acked: Arc::new(AtomicU64::new(0)),
            // v2 ring is allocated lazily at upstream-handshake time
            // (when v2 negotiation is confirmed and the registry has
            // capacity > 0). On resume hit it is restored from
            // `ParkedTcp::downlink_ring`.
            downlink_ring: None,
        }
    }
}

struct ChannelSink<Msg: Send + 'static> {
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
    metrics: Arc<Metrics>,
}

impl<Msg: Send + 'static> super::super::relay::UpstreamSink for ChannelSink<Msg> {
    async fn send_ciphertext(&mut self, ciphertext: Bytes) -> Result<()> {
        // Sample mpsc fill before push: `capacity()` returns the number
        // of free slots, so `max - capacity` is the live depth. Done
        // here rather than in the writer task because the writer holds
        // the receiver, and the sender side is the one that actually
        // back-pressures upstream reads.
        let used = self.tx.max_capacity().saturating_sub(self.tx.capacity());
        self.metrics
            .observe_ws_data_channel_fill(Transport::Tcp, AppProtocol::Shadowsocks, used);
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
    peer_addr: Option<SocketAddr>,
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
        AppProtocol::Shadowsocks,
    ));

    let mut decryptor = AeadStreamDecryptor::new(route.users.clone());
    // Try last-seen user first when this peer reconnects: cache hit avoids
    // O(N) HKDF + AEAD probes at handshake. The decryptor self-heals on a
    // stale hint by falling through to the full scan.
    if let Some(addr) = peer_addr
        && let Some(hint) = route.peer_user_cache.lookup(addr)
    {
        decryptor.set_user_hint(Some(hint));
    }
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
                            peer_addr,
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
                    server
                        .metrics
                        .record_pong_deadline_disconnect(Transport::Tcp, AppProtocol::Shadowsocks);
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
    let target_display = state.upstream_target_display.take().unwrap_or_else(|| Arc::from("?"));
    let owner = user.id_arc();
    let parked = ParkedTcp {
        upstream_writer: writer,
        upstream_reader: reader,
        target_display,
        owner: Arc::clone(&owner),
        protocol_context: TcpProtocolContext::Ss(user),
        user_counters,
        upstream_guard,
        // Move the Arc — the relay will get a fresh `Arc<AtomicU64>`
        // when (and if) it next runs without a resume hit. On a resume
        // hit the existing Arc is moved back into the new
        // WsTcpRelayState so the counter stays monotonic across parks.
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
        "parking tcp upstream into orphan registry",
    );
    server.orphan_registry.park(session_id, Parked::Tcp(parked));
    true
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_binary_frame<Msg>(
    state: &mut WsTcpRelayState,
    decryptor: &mut AeadStreamDecryptor,
    plaintext_buffer: &mut Vec<u8>,
    data: Bytes,
    server: &WsTcpServerCtx,
    route: &WsTcpRouteCtx,
    peer_addr: Option<SocketAddr>,
    outbound: WsTcpFrameOutput<'_, Msg>,
) -> Result<(), FrameError>
where
    Msg: Send + 'static,
{
    server.metrics.record_websocket_binary_frame(
        Transport::Tcp,
        route.protocol,
        AppProtocol::Shadowsocks,
        "in",
        data.len(),
    );
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

    // Back-fill the per-route hint as soon as authentication succeeds, so
    // the *next* connection from this peer skips the candidate scan. The
    // flag avoids re-locking the LRU shard on every subsequent binary
    // frame of an established session.
    if !state.peer_user_cache_recorded
        && let Some(addr) = peer_addr
        && let Some(idx) = decryptor.user_index()
    {
        route.peer_user_cache.record(addr, idx);
        state.peer_user_cache_recorded = true;
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

            // Ack-Prefix Protocol v1: when the client advertised the
            // capability we emit a 14-byte plaintext control frame here,
            // ahead of any upstream relay bytes, so the client can
            // replay only the bytes the upstream `TcpStream` has not
            // yet acked. The frame goes through the same AEAD
            // encryptor + WS sink as a normal data chunk; its FIFO
            // ordering on `outbound.data_tx` guarantees it lands at
            // the client before whatever the spawned relay task
            // produces. See `docs/SESSION-RESUMPTION.md` § Ack-Prefix
            // Protocol (v1).
            if state.ack_prefix_requested {
                let payload = ack_prefix::build_v1_payload(
                    parked.upstream_bytes_acked.load(Ordering::Relaxed),
                );
                let mut out = bytes::BytesMut::new();
                encryptor
                    .encrypt_chunk(&payload, &mut out)
                    .map_err(|e| FrameError::Fatal(anyhow!(e)))?;
                let ciphertext = out.split().freeze();
                let make_binary = outbound.make_binary;
                outbound.data_tx.send(make_binary(ciphertext)).await.map_err(|_| {
                    FrameError::Fatal(anyhow!(
                        "ack-prefix control frame send failed: WS data channel closed"
                    ))
                })?;
                debug!(
                    user = user.id(),
                    path = %route.path,
                    up_acked = parked.upstream_bytes_acked.load(Ordering::Relaxed),
                    "emitted ack-prefix control frame on resume hit",
                );
            }

            // v2 Symmetric Downlink Replay: emit the "ORDR" frame
            // immediately after the v1 frame when the protocol is
            // engaged. Replay payload is the contiguous suffix
            // `[client_acked_offset_request, total_sent_downlink)` from
            // the parked ring; missing-ring or eviction-rolled-past
            // surfaces as REPLAY_TRUNCATED + replay_len = 0. The frame
            // goes through the same AEAD encryptor + WS sink, in serial
            // order with the v1 frame.
            // See `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay (v2).
            if state.symmetric_replay_requested {
                use crate::server::resumption::downlink_ring::ReplayOutcome;
                let (flags, payload, ring_diag) = match parked.downlink_ring.as_ref() {
                    None => {
                        // The session was parked from a path that did
                        // not run the v2 ring (e.g. operator enabled
                        // v2 mid-session or the prior carrier did not
                        // capture). Honest answer is TRUNCATED.
                        (0x01u8, Vec::new(), None)
                    },
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
                                    user = user.id(),
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
                server.metrics.record_orphan_downlink_replay_bytes("tcp", payload_len);
                if truncated {
                    server.metrics.record_orphan_downlink_replay_truncated("tcp");
                }
                let mut frame = Vec::with_capacity(14 + payload.len());
                frame.extend_from_slice(b"ORDR");
                frame.push(0x01); // version
                frame.push(flags);
                frame.extend_from_slice(&payload_len.to_be_bytes());
                frame.extend_from_slice(&payload);
                let mut out = bytes::BytesMut::new();
                encryptor
                    .encrypt_chunk(&frame, &mut out)
                    .map_err(|e| FrameError::Fatal(anyhow!(e)))?;
                let ciphertext = out.split().freeze();
                let make_binary = outbound.make_binary;
                outbound.data_tx.send(make_binary(ciphertext)).await.map_err(|_| {
                    FrameError::Fatal(anyhow!(
                        "v2 downlink replay frame send failed: WS data channel closed"
                    ))
                })?;
                let (ring_oldest, ring_total) = ring_diag.unwrap_or((0, 0));
                debug!(
                    user = user.id(),
                    path = %route.path,
                    client_offset = state.client_acked_offset_request,
                    replay_len = payload_len,
                    truncated,
                    ring_oldest_offset = ring_oldest,
                    ring_total_sent = ring_total,
                    "emitted v2 downlink replay frame on resume hit",
                );
            }

            // Restore the parked downlink ring onto the new relay
            // state so subsequent upstream→client bytes continue
            // accumulating into the same buffer; survives any
            // future park.
            if state.symmetric_replay_requested {
                state.downlink_ring = parked.downlink_ring.clone().or_else(|| {
                    // Parked ring was absent (mid-deployment v2 enable).
                    // Allocate a fresh empty one so subsequent captures
                    // are retained for the next resume hit.
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
            let make_binary = outbound.make_binary;
            let make_close = outbound.make_close;
            let relay_metrics = Arc::clone(&server.metrics);
            let sink_metrics = Arc::clone(&server.metrics);
            let relay_user_id = Arc::clone(&user_id);
            let protocol = route.protocol;
            let cancel = Arc::new(Notify::new());
            let cancel_for_task = Arc::clone(&cancel);
            let parked_reader = parked.upstream_reader;
            state.upstream_to_client = Some(tokio::spawn(async move {
                super::super::relay::relay_upstream_to_client(
                    parked_reader,
                    ChannelSink {
                        tx,
                        make_binary,
                        make_close,
                        metrics: sink_metrics,
                    },
                    &mut encryptor,
                    relay_metrics,
                    protocol,
                    AppProtocol::Shadowsocks,
                    relay_user_id,
                    Some(cancel_for_task),
                    ring_for_task,
                )
                .await
            }));
            state.relay_cancel = Some(cancel);
            state.user_counters = Some(parked.user_counters);
            state.authenticated_user = Some(parked_user);
            state.upstream_writer = Some(parked.upstream_writer);
            state.upstream_guard = Some(parked.upstream_guard);
            state.upstream_target_display = Some(parked.target_display);
            // Move the parked counter back into the relay state so the
            // monotonic upstream-acked count survives this reattach.
            // Subsequent `forward_plaintext_to_writer` increments will
            // continue from the value the previous incarnation left
            // off at — exactly what the Ack-Prefix Protocol contract
            // requires of `up_acked`.
            state.upstream_bytes_acked = parked.upstream_bytes_acked;
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
                    AppProtocol::Shadowsocks,
                    "success",
                    connect_started.elapsed().as_secs_f64(),
                );
                stream
            },
            Err(error) => {
                server.metrics.record_tcp_connect(
                    Arc::clone(&user_id),
                    route.protocol,
                    AppProtocol::Shadowsocks,
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
        let sink_metrics = Arc::clone(&server.metrics);
        let relay_user_id = Arc::clone(&user_id);
        let protocol = route.protocol;
        // Cancel-notify is registered unconditionally so park-on-drop
        // can harvest the reader. When resumption is disabled the
        // notify is simply never fired and the relay loop runs in its
        // legacy single-arm mode.
        let cancel = Arc::new(Notify::new());
        let cancel_for_task = Arc::clone(&cancel);
        // v2 ring allocation at fresh-dial time. The capability bit on
        // `state.symmetric_replay_requested` is already gated at parse
        // time on (a) v1 also requested and (b) registry has v2
        // capacity > 0, so a `true` flag here is safe to honour.
        if state.symmetric_replay_requested && state.downlink_ring.is_none() {
            let cap = server.orphan_registry.downlink_buffer_bytes();
            if cap > 0 {
                state.downlink_ring = Some(Arc::new(parking_lot::Mutex::new(
                    crate::server::resumption::downlink_ring::DownlinkRing::new(cap),
                )));
            }
        }
        let ring_for_task = state.downlink_ring.clone();
        state.upstream_to_client = Some(tokio::spawn(async move {
            super::super::relay::relay_upstream_to_client(
                upstream_reader,
                ChannelSink {
                    tx,
                    make_binary,
                    make_close,
                    metrics: sink_metrics,
                },
                &mut encryptor,
                relay_metrics,
                protocol,
                AppProtocol::Shadowsocks,
                relay_user_id,
                Some(cancel_for_task),
                ring_for_task,
            )
            .await
        }));
        state.relay_cancel = Some(cancel);
        server.metrics.record_tcp_authenticated_session(
            Arc::clone(&user_id),
            route.protocol,
            AppProtocol::Shadowsocks,
        );
        state.upstream_guard = Some(server.metrics.open_tcp_upstream_connection(
            user_id,
            route.protocol,
            AppProtocol::Shadowsocks,
        ));
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
            counters
                .tcp_in(AppProtocol::Shadowsocks, protocol)
                .increment(plaintext_buffer.len() as u64);
        }
        let payload_len = plaintext_buffer.len() as u64;
        writer
            .write_all(plaintext_buffer)
            .await
            .context("failed to write decrypted data upstream")
            .map_err(FrameError::Fatal)?;
        // Bump the per-session upstream-acked counter only on successful
        // `write_all`. The kernel TCP send buffer accepts the bytes
        // here — past this point they belong to the upstream socket's
        // queue, even if the network later drops them. The Ack-Prefix
        // Protocol contract is "server forwarded N bytes to upstream",
        // and `write_all` succeeding is exactly that handoff.
        state.upstream_bytes_acked.fetch_add(payload_len, Ordering::Relaxed);
        plaintext_buffer.clear();
    }
    Ok(())
}

pub(super) async fn handle_tcp_connection(
    socket: WebSocket,
    server: Arc<WsTcpServerCtx>,
    route: WsTcpRouteCtx,
    resume: ResumeContext,
    peer_addr: Option<SocketAddr>,
) -> Result<()> {
    run_tcp_relay::<AxumWs>(AxumWs(socket), &server, &route, resume, peer_addr).await
}

pub(in crate::server) async fn handle_tcp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<WsTcpServerCtx>,
    route: WsTcpRouteCtx,
    resume: ResumeContext,
    peer_addr: Option<SocketAddr>,
) -> Result<()> {
    run_tcp_relay::<H3Ws>(H3Ws(socket), &server, &route, resume, peer_addr).await
}
