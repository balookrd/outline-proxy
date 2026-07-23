//! Home-side mesh relay: accept relayed carriers from edge peers and serve them
//! through the existing accept path.
//!
//! A relayed session arrives as a QUIC stream carrying an [`OpenHeader`] plus
//! the still-encrypted application bytes. We wrap the stream in a
//! [`MeshCarrier`] (a `WsSocket`) and hand it to the same `run_tcp_relay` /
//! `run_vless_relay` used for a direct carrier — so crypto, upstream and
//! park/unpark behave identically. The home authenticates the user from the
//! relayed stream itself (SS salt / VLESS UUID); the header only carries the
//! resume id, capabilities, path and client-address hint.
//!
//! Resume: the header's session id is both the requested resume id and the
//! issued id — the home parks under the id the client already holds (there is
//! no HTTP response over the mesh to echo a fresh one). See `docs/CLUSTER.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::extract::ws::WebSocketUpgrade;
use axum::response::Response;
use bytes::Bytes;
use outline_wire::cluster::ShardId;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tracing::{debug, warn};

use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    AcceptRelayError, CarrierKind, CloseReason, ControlDatagram, MeshStream, OpenHeader,
    PooledRelay, accept_relay, encode_throttle_hint, parse_control_datagram, read_datagram,
    write_datagram,
};
use crate::server::h3::vendored::{H3Stream, H3Transport, H3WebSocketStream};
use crate::server::resumption::SessionId;
use crate::server::shutdown::ShutdownSignal;
use crate::server::state::{
    RoutesSnapshot, Services, empty_transport_route, empty_vless_transport_route,
};

use super::carrier_padding;
use super::mesh_carrier::{MeshCarrier, MeshUdpCarrier};
use super::resume_headers::{EdgeResumeAdvert, ResumeContext, ResumeResponseEcho};
use super::tcp::{WsTcpRouteCtx, run_tcp_relay};
use super::throughput_monitor::ThrottleDetectParams;
use super::udp::{UdpRouteCtx, run_udp_relay};
use super::vless::{VlessWsRouteCtx, run_vless_relay};
use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};

/// Read granularity for the mesh→client direction on the edge.
const MESH_EDGE_CHUNK: usize = 256 * 1024;

/// What the edge needs to signal a throttled client segment to the home: the
/// mesh connection to send the control datagram on, the relayed session id to
/// key it, and the detection tunables. Built only when throttle detection is
/// enabled for the path (`None` otherwise, leaving the splice untouched).
pub(in crate::server) struct EdgeThrottleCtx {
    conn: Connection,
    session_id: [u8; 16],
    params: ThrottleDetectParams,
}

/// Builds the edge throttle-detection context for a relay, or `None` when
/// detection is off for `path`. Must be called before [`PooledRelay::into_parts`]
/// — it borrows the pooled relay's mesh connection.
pub(in crate::server) fn edge_throttle_ctx(
    pooled: &PooledRelay,
    session_id: SessionId,
    path: &str,
) -> Option<EdgeThrottleCtx> {
    carrier_padding::throttle_params_for_path(path).map(|params| EdgeThrottleCtx {
        conn: pooled.connection(),
        session_id: *session_id.as_bytes(),
        params,
    })
}

/// Edge-side detection of a throttled client segment, driven by how long each
/// downlink write to the client takes. When the home keeps feeding the edge but
/// the client stops draining, the client-facing `send` blocks; a send that
/// blocks past a detection window is a stalled window. Sustained past
/// `sustain_windows`, the edge sends one THROTTLE_HINT datagram to the home
/// (rate-limited by `signal_cooldown`), which injects an OCTL cover frame so the
/// client backs off.
///
/// The edge times `send` rather than reusing the home's rate-based
/// [`super::throughput_monitor::ThroughputMonitor`] because a slow mesh shows up
/// as a *read* stall (waiting on `mesh_recv`), not a *send* stall — only the
/// throttled client segment blocks the writer.
struct EdgeThrottleDetector {
    ctx: EdgeThrottleCtx,
    tracker: StallTracker,
    metrics: Arc<Metrics>,
}

impl EdgeThrottleDetector {
    fn new(ctx: EdgeThrottleCtx, metrics: Arc<Metrics>) -> Self {
        let tracker = StallTracker::new(&ctx.params);
        Self { ctx, tracker, metrics }
    }

    /// Feeds one client-facing send's elapsed time and the `bytes` it delivered;
    /// on a sustained stall that also cleared the low-bandwidth floor and the
    /// cooldown, fires one THROTTLE_HINT to the home. Fire-and-forget: an
    /// unreliable QUIC datagram, re-sent next window if lost, idempotent on the
    /// client.
    fn observe_send(&mut self, elapsed: Duration, bytes: usize) {
        if self.tracker.observe(elapsed, bytes, tokio::time::Instant::now()) {
            let _ = self
                .ctx
                .conn
                .send_datagram(Bytes::from(encode_throttle_hint(&self.ctx.session_id)));
            self.metrics.record_mesh_throttle_hint_sent();
            debug!("edge signalled a throttled client segment to the home");
        }
    }
}

/// Pure stall-streak tracker: the counting + floor + cooldown decision behind
/// [`EdgeThrottleDetector`], split out from the I/O so it is unit-testable
/// without a live mesh connection. A send spanning one or more detection windows
/// adds that many stalled windows to the streak (accumulating the bytes it
/// delivered and the time it took); a fast send resets it. Once the streak
/// reaches `sustain_windows`, the streak's delivered rate clears
/// `min_bytes_per_sec`, and the cooldown has elapsed, [`observe`] returns `true`
/// once and re-arms.
///
/// The floor keeps a genuinely slow (or idle) client from tripping a spurious
/// hint: the edge only sees how long each `send` blocks, and that delivered rate
/// is capped by the chunk over the window, so without a floor any client slow
/// enough to block would signal. A streak below the floor is suppressed but not
/// reset — if delivery climbs past the floor it can still fire.
///
/// [`observe`]: StallTracker::observe
struct StallTracker {
    window_secs: f64,
    sustain_windows: u32,
    min_bytes_per_sec: u64,
    cooldown: Duration,
    sustain: u32,
    stall_bytes: u64,
    stall_secs: f64,
    last_hint: Option<tokio::time::Instant>,
}

impl StallTracker {
    fn new(params: &ThrottleDetectParams) -> Self {
        Self {
            window_secs: params.window.as_secs_f64().max(0.001),
            sustain_windows: params.sustain_windows,
            min_bytes_per_sec: params.edge_min_bytes_per_sec,
            cooldown: params.signal_cooldown,
            sustain: 0,
            stall_bytes: 0,
            stall_secs: 0.0,
            last_hint: None,
        }
    }

    /// Feeds one send's `elapsed` time and delivered `bytes` at instant `now`;
    /// returns `true` exactly when a hint should fire (a sustained stall whose
    /// delivered rate clears the floor, past the cooldown), recording the
    /// cooldown start and resetting the streak.
    fn observe(&mut self, elapsed: Duration, bytes: usize, now: tokio::time::Instant) -> bool {
        let windows = (elapsed.as_secs_f64() / self.window_secs).floor() as u32;
        if windows >= 1 {
            self.sustain = self.sustain.saturating_add(windows);
            self.stall_bytes = self.stall_bytes.saturating_add(bytes as u64);
            self.stall_secs += elapsed.as_secs_f64();
        } else {
            self.sustain = 0;
            self.stall_bytes = 0;
            self.stall_secs = 0.0;
        }
        if self.sustain < self.sustain_windows {
            return false;
        }
        // Low-bandwidth floor: a sustained stall that delivered too little to the
        // client is a slow/idle client, not an actionable throttle. Stay quiet
        // but keep the streak so a later pickup past the floor can still fire.
        let delivered_rate = if self.stall_secs > 0.0 {
            self.stall_bytes as f64 / self.stall_secs
        } else {
            0.0
        };
        if delivered_rate < self.min_bytes_per_sec as f64 {
            return false;
        }
        let cooled = self.last_hint.is_none_or(|t| now.duration_since(t) >= self.cooldown);
        if !cooled {
            return false;
        }
        self.last_hint = Some(now);
        self.sustain = 0;
        self.stall_bytes = 0;
        self.stall_secs = 0.0;
        true
    }
}

/// Edge-side relay: splice a client carrier to a mesh relay stream, forwarding
/// the still-encrypted application bytes both ways. The edge does not decode
/// the SS/VLESS layer — it moves the WS binary payload verbatim (padding +
/// ciphertext) so the home strips both. Exactly one writer per direction, so
/// backpressure rides the QUIC / WS windows (mirrors [`super::mesh_carrier`]
/// on the home side). Validated end to end by the phase-8 test.
///
/// Known v1 limitation (h1/h2 client carriers only): the edge drops the
/// client's keepalive `Ping` rather than answering `Pong`, because a single
/// writer owns the client downlink and interleaving a control reply would
/// break that invariant. A fully idle session therefore relies on the client's
/// own reconnect; an H3 client carrier is unaffected (QUIC keep-alive holds
/// liveness and the client swallows its own Ping).
///
/// Health budget: `budget` bounds a single uplink write to the mesh. When the
/// home stops draining (hung or the cross-country interconnect stalls), the
/// QUIC send window fills and the write blocks; exceeding `budget` means a
/// stalled relay, so we reset the mesh stream with [`CloseReason::Budget`] and
/// fail — the client reconnects and gets a fresh session (the home parks the
/// upstream, which then TTL-expires). It measures *progress*, not RTT: a high
/// but flowing RTT keeps completing writes, so this only fires on a full stall.
/// It never false-fires on an idle session — an idle uplink blocks on `recv`,
/// not on a write. Pure-download stalls (no uplink to push) are left to the
/// mesh QUIC idle timeout. See `docs/CLUSTER.md` § Health budget.
pub(in crate::server::transport) async fn edge_relay<T: WsSocket>(
    client: T,
    mut mesh_send: SendStream,
    mut mesh_recv: RecvStream,
    budget: Duration,
    detect: Option<EdgeThrottleCtx>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let (mut reader, mut writer) = client.split_io();
    // `role="edge"` byte counters: up = client→mesh (toward home), down =
    // mesh→client. Resolved once; incremented per relayed chunk in each leg.
    let up_bytes = metrics.mesh_bytes_counter("edge", "up", "tcp");
    let down_bytes = metrics.mesh_bytes_counter("edge", "down", "tcp");

    // Uplink: the ONLY writer to `mesh_send`.
    let uplink = async {
        while let Some(msg) = T::recv(&mut reader).await? {
            match T::classify(msg) {
                WsFrame::Binary(data) => {
                    match tokio::time::timeout(budget, mesh_send.write_all(&data)).await {
                        Ok(result) => result.context("mesh edge uplink write")?,
                        Err(_elapsed) => {
                            // Stalled past the budget: the home is not draining.
                            let _ = mesh_send.reset(VarInt::from_u32(CloseReason::Budget.code()));
                            bail!("mesh relay stalled past the health budget");
                        },
                    }
                    up_bytes.increment(data.len() as u64);
                },
                WsFrame::Close => break,
                // The edge does not interpret the carrier; drop control frames.
                WsFrame::Ping(_) | WsFrame::Pong | WsFrame::Text => {},
            }
        }
        let _ = mesh_send.finish();
        Ok::<(), anyhow::Error>(())
    };

    // Downlink: the ONLY writer to the client `writer`. When detection is on,
    // time each client-facing send: a send that blocks means the client isn't
    // draining (edge→client throttle).
    let downlink = async {
        let mut detector = detect.map(|ctx| EdgeThrottleDetector::new(ctx, Arc::clone(&metrics)));
        while let Some(chunk) = mesh_recv
            .read_chunk(MESH_EDGE_CHUNK, true)
            .await
            .context("mesh edge downlink read")?
        {
            let bytes = chunk.bytes.len();
            let msg = T::binary_msg(chunk.bytes);
            match detector.as_mut() {
                Some(d) => {
                    let started = tokio::time::Instant::now();
                    T::send(&mut writer, msg)
                        .await
                        .context("edge client downlink write")?;
                    d.observe_send(started.elapsed(), bytes);
                },
                None => {
                    T::send(&mut writer, msg)
                        .await
                        .context("edge client downlink write")?;
                },
            }
            down_bytes.increment(bytes as u64);
        }
        T::finish(&mut writer).await;
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

/// Edge-side relay for SS-UDP: like [`edge_relay`] but preserves datagram
/// boundaries. An SS-UDP packet is atomic — one client `Binary` frame is one
/// AEAD-sealed packet with no length prefix — so a raw byte splice would let
/// QUIC coalesce or split packets and the home's per-packet AEAD open would then
/// fail on a mis-boundaried buffer. Each direction therefore length-frames the
/// datagram onto the mesh stream ([`write_datagram`]) and de-frames it off the
/// other side ([`read_datagram`]). One writer per direction, so backpressure
/// rides the QUIC / WS windows. The health `budget` bounds a single uplink
/// datagram write exactly as in [`edge_relay`].
pub(in crate::server::transport) async fn edge_relay_udp<T: WsSocket>(
    client: T,
    mut mesh_send: SendStream,
    mut mesh_recv: RecvStream,
    budget: Duration,
    detect: Option<EdgeThrottleCtx>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let (mut reader, mut writer) = client.split_io();
    // `role="edge"` byte + datagram counters, one pair per direction.
    let up_bytes = metrics.mesh_bytes_counter("edge", "up", "udp");
    let up_datagrams = metrics.mesh_datagrams_counter("edge", "up");
    let down_bytes = metrics.mesh_bytes_counter("edge", "down", "udp");
    let down_datagrams = metrics.mesh_datagrams_counter("edge", "down");

    // Uplink: the ONLY writer to `mesh_send`. One client Binary = one datagram.
    let uplink = async {
        while let Some(msg) = T::recv(&mut reader).await? {
            match T::classify(msg) {
                WsFrame::Binary(data) => {
                    match tokio::time::timeout(budget, write_datagram(&mut mesh_send, &data)).await
                    {
                        Ok(result) => result.context("mesh edge uplink datagram write")?,
                        Err(_elapsed) => {
                            // Stalled past the budget: the home is not draining.
                            let _ = mesh_send.reset(VarInt::from_u32(CloseReason::Budget.code()));
                            bail!("mesh relay stalled past the health budget");
                        },
                    }
                    up_bytes.increment(data.len() as u64);
                    up_datagrams.increment(1);
                },
                WsFrame::Close => break,
                // The edge does not interpret the carrier; drop control frames.
                WsFrame::Ping(_) | WsFrame::Pong | WsFrame::Text => {},
            }
        }
        let _ = mesh_send.finish();
        Ok::<(), anyhow::Error>(())
    };

    // Downlink: the ONLY writer to the client `writer`. One datagram = one Binary.
    // When detection is on, time each client-facing send (see [`edge_relay`]).
    let downlink = async {
        let mut detector = detect.map(|ctx| EdgeThrottleDetector::new(ctx, Arc::clone(&metrics)));
        let mut buf = Vec::new();
        while let Some(len) = read_datagram(&mut mesh_recv, &mut buf)
            .await
            .context("mesh edge downlink datagram read")?
        {
            let msg = T::binary_msg(Bytes::copy_from_slice(&buf[..len]));
            match detector.as_mut() {
                Some(d) => {
                    let started = tokio::time::Instant::now();
                    T::send(&mut writer, msg)
                        .await
                        .context("edge client downlink datagram write")?;
                    d.observe_send(started.elapsed(), len);
                },
                None => {
                    T::send(&mut writer, msg)
                        .await
                        .context("edge client downlink datagram write")?;
                },
            }
            down_bytes.increment(len as u64);
            down_datagrams.increment(1);
        }
        T::finish(&mut writer).await;
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(uplink, downlink)?;
    Ok(())
}

/// Opens a mesh relay to the home for an edge-routed carrier: builds the OPEN
/// header from the client's advertisement and dials the home. Returns the
/// pooled relay on success (the caller splices the client carrier into it and
/// echoes `advert.session_id` for continuity), or `None` when the relay is
/// unavailable (the caller serves a fresh local session instead). Carrier-
/// agnostic, so the axum (h1/h2) and h3 accept paths share it.
pub(in crate::server) async fn open_edge_relay(
    cluster: &ClusterCtx,
    shard: ShardId,
    advert: &EdgeResumeAdvert,
    carrier: CarrierKind,
    path: &str,
    peer_addr: SocketAddr,
) -> Option<PooledRelay> {
    let header = OpenHeader {
        carrier,
        session_id: *advert.session_id.as_bytes(),
        resume_capable: advert.resume_capable,
        ack_prefix: advert.ack_prefix,
        symmetric_replay: advert.symmetric_replay,
        client_down_acked: advert.down_acked,
        path: path.to_string(),
        peer_addr: Some(peer_addr),
    };
    match cluster.pool.open_relay(shard, &header).await {
        Ok(pooled) => {
            cluster.metrics.record_mesh_relay_opened("ok");
            Some(pooled)
        },
        Err(error) => {
            cluster.metrics.record_mesh_relay_opened("fail");
            debug!(
                ?error,
                shard = shard.get(),
                "mesh relay open failed; serving a fresh local session",
            );
            None
        },
    }
}

/// Splices an h3 client carrier to an already-opened mesh relay. The h3 accept
/// path holds the carrier directly (not behind an `on_upgrade` closure), so it
/// calls this after sending the extended-CONNECT response. Wraps the stream in
/// the `H3Ws` `WsSocket` and holds the pool permit for the relay's lifetime.
pub(in crate::server) async fn edge_relay_h3(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    pooled: PooledRelay,
    budget: Duration,
    detect: Option<EdgeThrottleCtx>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let (send, recv, _permit) = pooled.into_parts();
    edge_relay::<H3Ws>(H3Ws(socket), send, recv, budget, detect, metrics).await
}

/// SS-UDP twin of [`edge_relay_h3`]: splices an h3 client carrier to a mesh
/// relay with datagram framing, so per-packet SS-UDP boundaries survive the hop.
pub(in crate::server) async fn edge_relay_h3_udp(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    pooled: PooledRelay,
    budget: Duration,
    detect: Option<EdgeThrottleCtx>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let (send, recv, _permit) = pooled.into_parts();
    edge_relay_udp::<H3Ws>(H3Ws(socket), send, recv, budget, detect, metrics).await
}

/// Describes a carrier the edge is about to relay to its home. Bundled so the
/// TCP and VLESS upgrade call sites stay readable.
pub(in crate::server::transport) struct EdgeRelay {
    /// Home shard the resume id decoded to.
    pub(in crate::server::transport) shard: ShardId,
    /// Raw client resume advertisement to carry in the OPEN header.
    pub(in crate::server::transport) advert: EdgeResumeAdvert,
    /// Carrier kind (already resolved to a Tcp/Udp leg for combined-SS).
    pub(in crate::server::transport) carrier: CarrierKind,
    /// Request path, for the home's padding-scheme selection and routing.
    pub(in crate::server::transport) path: Arc<str>,
    /// Client address hint (logging / routing scope on the home).
    pub(in crate::server::transport) peer_addr: SocketAddr,
    /// HTTP version of the client carrier (metrics label).
    pub(in crate::server::transport) protocol: Protocol,
    /// Application protocol of the carrier (metrics label).
    pub(in crate::server::transport) app_protocol: AppProtocol,
    /// Short carrier name for session-teardown logging (`"tcp"` / `"vless"`).
    pub(in crate::server::transport) kind: &'static str,
}

/// Edge side: relay a foreign-shard carrier to its home over the mesh.
///
/// The mesh relay is opened **before** the WebSocket `101` handshake so the
/// echoed session id reflects the real outcome. On success the returned
/// response upgrades the client carrier and splices it byte-for-byte to the
/// home, echoing the id the client already holds (the home parks the upstream
/// under exactly that id — continuity across the edge switch). On failure the
/// [`WebSocketUpgrade`] is handed back so the caller serves a fresh local
/// session instead (this edge becomes the new home and mints its own id).
pub(in crate::server::transport) async fn try_relay_edge(
    ws: WebSocketUpgrade,
    cluster: &ClusterCtx,
    metrics: &Arc<Metrics>,
    relay: EdgeRelay,
) -> std::result::Result<Response, WebSocketUpgrade> {
    let EdgeRelay {
        shard,
        advert,
        carrier,
        path,
        peer_addr,
        protocol,
        app_protocol,
        kind,
    } = relay;
    let Some(pooled) = open_edge_relay(cluster, shard, &advert, carrier, &path, peer_addr).await
    else {
        return Err(ws);
    };
    let session = metrics.open_websocket_session(Transport::Tcp, protocol, app_protocol);
    let budget = cluster.relay_budget;
    // Edge throttle detection (built before `pooled` moves into the closure; it
    // clones the mesh connection, so it is independent of the relay streams).
    let detect = edge_throttle_ctx(&pooled, advert.session_id, &path);
    // Continuity: echo the id the client presented — the home parks the relayed
    // upstream under exactly that id, so the client keeps resuming it.
    let echo = ResumeResponseEcho {
        session_id: Some(advert.session_id),
        ..Default::default()
    };
    let relay_metrics = Arc::clone(metrics);
    let mut response = ws.on_upgrade(move |socket| async move {
        // Hold the pool permit for the relay's whole lifetime (drops here).
        let (send, recv, _permit) = pooled.into_parts();
        let result =
            edge_relay::<AxumWs>(AxumWs(socket), send, recv, budget, detect, relay_metrics).await;
        super::finish_ws_session(session, result, kind);
    });
    echo.apply(response.headers_mut());
    Ok(response)
}

/// Edge side: relay a foreign-shard SS-UDP carrier to its home over the mesh.
///
/// The UDP twin of [`try_relay_edge`]: same open-before-`101` continuity dance
/// (echo the id the client already holds so the home parks under it), but the
/// carrier is spliced with [`edge_relay_udp`] to preserve datagram boundaries
/// and metrics are labelled UDP. Takes the same [`EdgeRelay`] bundle (with
/// `carrier` = [`CarrierKind::SsUdp`]); `peer_addr` is a client hint carried in
/// the OPEN header that the UDP relay does not need for routing.
pub(in crate::server::transport) async fn try_relay_edge_udp(
    ws: WebSocketUpgrade,
    cluster: &ClusterCtx,
    metrics: &Arc<Metrics>,
    relay: EdgeRelay,
) -> std::result::Result<Response, WebSocketUpgrade> {
    let EdgeRelay {
        shard,
        advert,
        carrier,
        path,
        peer_addr,
        protocol,
        app_protocol,
        kind,
    } = relay;
    let Some(pooled) = open_edge_relay(cluster, shard, &advert, carrier, &path, peer_addr).await
    else {
        return Err(ws);
    };
    let session = metrics.open_websocket_session(Transport::Udp, protocol, app_protocol);
    let budget = cluster.relay_budget;
    let detect = edge_throttle_ctx(&pooled, advert.session_id, &path);
    let echo = ResumeResponseEcho {
        session_id: Some(advert.session_id),
        ..Default::default()
    };
    let relay_metrics = Arc::clone(metrics);
    let mut response = ws.on_upgrade(move |socket| async move {
        let (send, recv, _permit) = pooled.into_parts();
        let result =
            edge_relay_udp::<AxumWs>(AxumWs(socket), send, recv, budget, detect, relay_metrics)
                .await;
        super::finish_ws_session(session, result, kind);
    });
    echo.apply(response.headers_mut());
    Ok(response)
}

/// Accepts relayed connections from edge peers until the endpoint closes or the
/// server shuts down. One task per peer connection; one task per relayed
/// session on it.
pub(in crate::server) async fn run_mesh_listener(
    cluster: Arc<ClusterCtx>,
    services: Arc<Services>,
    routes: RoutesSnapshot,
    mut shutdown: ShutdownSignal,
) -> Result<()> {
    loop {
        tokio::select! {
            accepted = cluster.endpoint.accept() => {
                match accepted {
                    Some(Ok(conn)) => {
                        let cluster = Arc::clone(&cluster);
                        let services = Arc::clone(&services);
                        let routes = Arc::clone(&routes);
                        tokio::spawn(handle_mesh_connection(conn, cluster, services, routes));
                    },
                    Some(Err(error)) => debug!(?error, "mesh peer connection failed"),
                    None => break, // endpoint closed
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
    Ok(())
}

/// Serves every relay stream a peer opens on `conn` until it closes.
async fn handle_mesh_connection(
    conn: quinn::Connection,
    cluster: Arc<ClusterCtx>,
    services: Arc<Services>,
    routes: RoutesSnapshot,
) {
    // Per-connection control-datagram receiver: routes each THROTTLE_HINT to the
    // matching relay's carrier monitor by session id (waking its writer to inject
    // an OCTL cover frame). Best-effort — a malformed or unknown-session datagram
    // is dropped. Bounded: `read_datagram` errors when the connection closes, and
    // the `AbortOnDrop` guard tears the task down when this connection ends.
    let _control_rx = {
        let cluster = Arc::clone(&cluster);
        let conn = conn.clone();
        crate::server::abort::AbortOnDrop::new(tokio::spawn(async move {
            while let Ok(datagram) = conn.read_datagram().await {
                match parse_control_datagram(&datagram) {
                    Ok(ControlDatagram::ThrottleHint { session_id }) => {
                        let outcome = if cluster.throttle_registry.route_hint(&session_id) {
                            "delivered"
                        } else {
                            "dropped"
                        };
                        cluster.metrics.record_mesh_throttle_hint_received(outcome);
                    },
                    Err(error) => {
                        cluster.metrics.record_mesh_control_datagram_error();
                        debug!(?error, "dropping malformed mesh control datagram");
                    },
                }
            }
        }))
    };

    // Ends only when the peer closes the connection. A stream that fails on its
    // way in is dropped on its own: the connection is still carrying every relay
    // already accepted on it, plus the control-datagram receiver above.
    loop {
        let (header, stream) = match accept_relay(&conn).await {
            Ok(accepted) => accepted,
            Err(AcceptRelayError::Connection(error)) => {
                debug!(?error, "mesh peer connection ended");
                break;
            },
            Err(AcceptRelayError::Stream(error)) => {
                debug!(?error, "dropping an unusable mesh relay stream");
                continue;
            },
        };
        // Bounded resources: one permit per served relay, held for its lifetime.
        // Refusing beyond the cap keeps a degraded peer — one opening streams in
        // a loop — from growing this home's task/socket footprint without bound.
        // A refused edge fails fast and serves its client locally instead.
        let Ok(permit) = Arc::clone(&cluster.relay_permits).try_acquire_owned() else {
            cluster.metrics.record_mesh_relay_rejected("capacity");
            warn!("mesh relayed-session cap reached; refusing a relay stream");
            refuse_relay(stream, CloseReason::Capacity);
            continue;
        };
        let cluster = Arc::clone(&cluster);
        let services = Arc::clone(&services);
        let routes = Arc::clone(&routes);
        tokio::spawn(async move {
            // Releases the slot when the relay ends, on every path.
            let _permit = permit;
            if let Err(error) = serve_relayed(header, stream, &cluster, &services, &routes).await {
                debug!(?error, "relayed session ended with error");
            }
        });
    }
}

/// Refuses one relay stream, resetting both halves with `reason` so the edge
/// learns of the refusal on its next read or write instead of waiting out its
/// health budget.
fn refuse_relay(stream: MeshStream, reason: CloseReason) {
    let MeshStream { mut send, mut recv } = stream;
    let code = VarInt::from_u32(reason.code());
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

/// Logs a one-shot diagnostic when a relayed carrier resolves to an empty route
/// table on the home. Every stream/datagram on an empty route fails
/// authentication (no configured key matches) and is dropped, so without this a
/// home/edge path- or carrier-table mismatch is a silent black hole — the exact
/// failure the SS-UDP relay hit. Only reachable under an asymmetric cluster
/// config; a symmetric cluster (shared PSK + matching config, the supported
/// topology) always resolves the path. Fires once per relayed session, not per
/// datagram, so it stays low-noise.
fn warn_if_empty_relayed_route(is_empty: bool, carrier: CarrierKind, path: &str) {
    if is_empty {
        warn!(
            ?carrier,
            path,
            "relayed carrier resolved to an empty route on the home; every packet will fail \
             authentication and be dropped — check that this home serves the edge's path and \
             carrier (cluster config must be symmetric)"
        );
    }
}

/// Dispatches one relayed carrier into the matching accept path.
async fn serve_relayed(
    header: OpenHeader,
    stream: MeshStream,
    cluster: &ClusterCtx,
    services: &Services,
    routes: &RoutesSnapshot,
) -> Result<()> {
    // The carrier wrapping the mesh stream is built inside each arm: the
    // TCP/VLESS carriers use the byte-stream `MeshCarrier`, while SS-UDP uses
    // the datagram-framed `MeshUdpCarrier` (moving `stream` into the arm taken).
    let path: Arc<str> = Arc::from(header.path.as_str());
    let padding = carrier_padding::scheme_for_path(&path);
    let session_id = SessionId::from_bytes(header.session_id);
    // The home parks under the id the client already holds; there is no HTTP
    // response over the mesh to hand back a freshly minted one.
    let resume = ResumeContext {
        requested_resume: Some(session_id),
        issued_session_id: Some(session_id),
        ack_prefix_requested: header.ack_prefix,
        symmetric_replay_requested: header.symmetric_replay,
        client_acked_offset: header.client_down_acked,
    };
    let peer_addr = header.peer_addr;
    // The `*Xhttp` carriers differ only in which route table holds the path.
    let protocol = match header.carrier {
        CarrierKind::SsXhttp | CarrierKind::VlessXhttp | CarrierKind::SsUdpXhttp => {
            Protocol::XhttpH3
        },
        _ => Protocol::Http3,
    };

    // Downstream-throttle monitor for this relayed carrier. Built here (not in
    // the relay) so it can be registered under the session id: the home cannot
    // detect the throttled edge→client segment locally, so the mesh control-
    // datagram receiver wakes this writer from an edge THROTTLE_HINT instead. The
    // registration guard lives across the relay (dropped when this fn returns).
    // `None` when detection is off for this path — the relay then behaves exactly
    // as before (byte-for-byte identical wire).
    let throttle_monitor = carrier_padding::throttle_params_for_path(&path)
        .map(super::throughput_monitor::ThroughputMonitor::new);
    let _throttle_registration = throttle_monitor
        .as_ref()
        .map(|m| cluster.throttle_registry.register(header.session_id, m));

    // Count this relay as active on the home for its whole lifetime; the guard
    // drops (decrementing the gauge) on return, including every early bail.
    let _relay_active = cluster.metrics.open_mesh_relay();

    match header.carrier {
        CarrierKind::SsTcp | CarrierKind::SsXhttp => {
            let route = {
                let snap = routes.load();
                let map = if header.carrier == CarrierKind::SsXhttp {
                    &snap.xhttp_ss
                } else {
                    &snap.tcp
                };
                map.get(&*path).cloned().unwrap_or_else(empty_transport_route)
            };
            warn_if_empty_relayed_route(route.users.is_empty(), header.carrier, &path);
            let route_ctx = WsTcpRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: Arc::clone(&path),
                candidate_users: Arc::clone(&route.candidate_users),
                peer_user_cache: Arc::clone(&route.peer_user_cache),
                padding,
            };
            run_tcp_relay(
                MeshCarrier::new(
                    stream,
                    cluster.metrics.mesh_bytes_counter("home", "up", "tcp"),
                    cluster.metrics.mesh_bytes_counter("home", "down", "tcp"),
                ),
                &services.tcp_server,
                &route_ctx,
                resume,
                peer_addr,
                throttle_monitor.clone(),
            )
            .await
        },
        CarrierKind::VlessTcp | CarrierKind::VlessXhttp => {
            let route = {
                let snap = routes.load();
                let map = if header.carrier == CarrierKind::VlessXhttp {
                    &snap.xhttp_vless
                } else {
                    &snap.vless
                };
                map.get(&*path).cloned().unwrap_or_else(empty_vless_transport_route)
            };
            warn_if_empty_relayed_route(route.users.is_empty(), header.carrier, &path);
            let route_ctx = VlessWsRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: Arc::clone(&path),
                candidate_users: Arc::clone(&route.candidate_users),
                padding,
                peer: peer_addr.map(|addr| addr.ip()),
            };
            run_vless_relay(
                MeshCarrier::new(
                    stream,
                    cluster.metrics.mesh_bytes_counter("home", "up", "tcp"),
                    cluster.metrics.mesh_bytes_counter("home", "down", "tcp"),
                ),
                &services.vless_server,
                &route_ctx,
                resume,
                throttle_monitor.clone(),
            )
            .await
        },
        CarrierKind::SsUdp | CarrierKind::SsUdpXhttp => {
            let route = {
                let snap = routes.load();
                let map = if header.carrier == CarrierKind::SsUdpXhttp {
                    &snap.xhttp_ss_udp
                } else {
                    &snap.udp
                };
                map.get(&*path).cloned().unwrap_or_else(empty_transport_route)
            };
            warn_if_empty_relayed_route(route.users.is_empty(), header.carrier, &path);
            let route_ctx = Arc::new(UdpRouteCtx {
                users: Arc::clone(&route.users),
                protocol,
                path: Arc::clone(&path),
                candidate_users: Arc::clone(&route.candidate_users),
                padding,
            });
            // Datagram-framed carrier keeps SS-UDP packet boundaries intact
            // across the mesh; the existing UDP relay owns NAT/park/unpark.
            run_udp_relay(
                MeshUdpCarrier::new(
                    stream,
                    cluster.metrics.mesh_bytes_counter("home", "up", "udp"),
                    cluster.metrics.mesh_bytes_counter("home", "down", "udp"),
                    cluster.metrics.mesh_datagrams_counter("home", "up"),
                    cluster.metrics.mesh_datagrams_counter("home", "down"),
                ),
                Arc::clone(&services.udp_server),
                route_ctx,
                resume,
                throttle_monitor.clone(),
            )
            .await
        },
        CarrierKind::VlessUdp => {
            // Unreachable in practice: an edge never builds a VlessUdp carrier.
            // VLESS-UDP rides the VlessTcp carrier — the edge forwards the VLESS
            // byte stream verbatim and the home's `run_vless_relay` parses the
            // UDP command from it. Kept as a defensive close (not a panic) in
            // case a peer sends a forged or mismatched-version header.
            warn!("unexpected VlessUdp mesh carrier (VLESS-UDP rides VlessTcp); dropping");
            bail!("VlessUdp mesh carrier is unreachable on the edge")
        },
    }
}

#[cfg(test)]
#[path = "tests/mesh_relay.rs"]
mod tests;
