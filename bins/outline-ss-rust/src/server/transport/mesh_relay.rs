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
//!
//! Two wire versions are served side by side while the fleet migrates. The
//! paragraph above describes v4, which [`serve_relayed`] still implements
//! unchanged. In v5 the *edge* terminates the client's crypto and the mesh
//! carries application plaintext, so [`serve_relayed_v5`] resolves a park and
//! splices onto it directly — no route table, no crypto, no accept path. The
//! accept loop dispatches on the OPEN version byte; the two paths share only
//! the stream and the refusal helper.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::extract::ws::WebSocketUpgrade;
use axum::response::Response;
use bytes::Bytes;
use outline_wire::cluster::ShardId;
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};
use crate::server::cluster::ClusterCtx;
use crate::server::cluster::mesh::{
    AcceptRelayError, CarrierKind, CloseReason, ControlDatagram, MAX_USER_LEN, MeshFraming,
    MeshStream, OpenHeader, OpenHeaderV5, PooledRelay, RelayOpen, UserFrame, accept_relay,
    encode_throttle_hint, parse_control_datagram, read_datagram, write_datagram, write_open_ack,
};
use crate::server::h3::vendored::{H3Stream, H3Transport, H3WebSocketStream};
use crate::server::resumption::downlink_ring::ReplayOutcome;
use crate::server::resumption::{
    OrphanRegistry, Parked, ParkedTcp, ResumeMiss, ResumeOutcome, SessionId,
};
use crate::server::shutdown::ShutdownSignal;
use crate::server::state::{
    RoutesSnapshot, Services, TransportRoute, VlessTransportRoute, empty_transport_route,
    empty_vless_transport_route,
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

/// Read granularity of the home's v5 plaintext splice, in both directions. Also
/// the size of the single upstream read buffer the splice allocates once per
/// relay — the explicit bound on that buffer.
const MESH_HOME_SPLICE_CHUNK: usize = 64 * 1024;

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
/// header from the client's advertisement, dials the home and waits for its
/// setup acknowledgement. Returns the pooled relay on success (the caller
/// splices the client carrier into it and echoes `advert.session_id` for
/// continuity), or `None` when the relay is unavailable (the caller serves a
/// fresh local session instead). Carrier-agnostic, so the axum (h1/h2) and h3
/// accept paths share it.
///
/// Waiting for the ack costs one mesh RTT before the `101`, and buys the
/// difference between a relay that works and a black hole: a home that does not
/// serve this path/carrier refuses here, while the client carrier is still
/// un-upgraded and the caller can still serve it locally. Without the wait the
/// refusal would only surface once bytes were already flowing — after the
/// client had been committed to a relay that drops every packet.
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
    let mut pooled = match cluster.pool.open_relay(shard, &header).await {
        Ok(pooled) => pooled,
        Err(error) => {
            cluster.metrics.record_mesh_relay_opened("fail");
            debug!(
                ?error,
                shard = shard.get(),
                "mesh relay open failed; serving a fresh local session",
            );
            return None;
        },
    };
    // The home admits or refuses before the client carrier is upgraded. A
    // refusal is counted apart from an unreachable home: it means the peer is
    // healthy but cannot serve this path/carrier, which is a config mismatch to
    // fix, not a transport fault.
    if let Err(error) = pooled.await_ack(cluster.relay_budget).await {
        cluster.metrics.record_mesh_relay_opened("refused");
        warn!(
            ?error,
            shard = shard.get(),
            path,
            "home refused the mesh relay; serving a fresh local session — check that the home \
             serves this path and carrier (cluster config must be symmetric)",
        );
        return None;
    }
    cluster.metrics.record_mesh_relay_opened("ok");
    Some(pooled)
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
            // Version dispatch. Both wire versions are served while the fleet
            // runs a mix: a v4 edge still relays its still-encrypted carrier
            // into the legacy path, a v5 edge relays plaintext for a park this
            // home owns. An unknown version never reaches here — `accept_relay`
            // already refused it as an unparsable stream.
            let result = match header {
                RelayOpen::V4(header) => {
                    serve_relayed(header, stream, &cluster, &services, &routes).await
                },
                RelayOpen::V5(header) => {
                    serve_relayed_v5(header, stream, &cluster, &services).await
                },
            };
            if let Err(error) = result {
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

/// The home-side route a relayed carrier will authenticate against, resolved
/// once from the OPEN header's path and carrier kind.
enum RelayedRoute {
    /// Shadowsocks route table entry (`SsTcp` / `SsUdp` and their `*Xhttp` twins).
    Ss(Arc<TransportRoute>),
    /// VLESS route table entry (`VlessTcp` / `VlessXhttp`).
    Vless(Arc<VlessTransportRoute>),
}

impl RelayedRoute {
    /// Whether the path resolved to no configured users. Such a route holds no
    /// key, so every stream/datagram relayed onto it fails authentication.
    fn is_empty(&self) -> bool {
        match self {
            RelayedRoute::Ss(route) => route.users.is_empty(),
            RelayedRoute::Vless(route) => route.users.is_empty(),
        }
    }
}

/// Resolves the relayed carrier's path against the route table its kind uses.
/// The `*Xhttp` kinds differ from the WS kinds only in which table holds the
/// path. `None` for [`CarrierKind::VlessUdp`], which owns no route table (it is
/// unreachable in practice — VLESS-UDP rides the `VlessTcp` carrier).
fn resolve_relayed_route(
    routes: &RoutesSnapshot,
    carrier: CarrierKind,
    path: &str,
) -> Option<RelayedRoute> {
    let snap = routes.load();
    Some(match carrier {
        CarrierKind::SsTcp => {
            RelayedRoute::Ss(snap.tcp.get(path).cloned().unwrap_or_else(empty_transport_route))
        },
        CarrierKind::SsXhttp => {
            RelayedRoute::Ss(snap.xhttp_ss.get(path).cloned().unwrap_or_else(empty_transport_route))
        },
        CarrierKind::SsUdp => {
            RelayedRoute::Ss(snap.udp.get(path).cloned().unwrap_or_else(empty_transport_route))
        },
        CarrierKind::SsUdpXhttp => RelayedRoute::Ss(
            snap.xhttp_ss_udp
                .get(path)
                .cloned()
                .unwrap_or_else(empty_transport_route),
        ),
        CarrierKind::VlessTcp => RelayedRoute::Vless(
            snap.vless
                .get(path)
                .cloned()
                .unwrap_or_else(empty_vless_transport_route),
        ),
        CarrierKind::VlessXhttp => RelayedRoute::Vless(
            snap.xhttp_vless
                .get(path)
                .cloned()
                .unwrap_or_else(empty_vless_transport_route),
        ),
        CarrierKind::VlessUdp => return None,
    })
}

/// Refuses a relayed carrier whose path and kind resolve to no configured users
/// on this home, and says why.
///
/// Serving it instead would be a black hole: the relay would run against a route
/// holding no key, so every stream/datagram on it fails authentication and is
/// dropped, for the life of the session, with the client seeing only silence.
/// That is exactly what an asymmetric cluster config produced in production. A
/// reset carrying [`CloseReason::NoRoute`] instead fails the setup fast and
/// explicitly, so the edge serves its client a fresh local session. Only
/// reachable under an asymmetric config; a symmetric cluster (shared PSK +
/// matching paths and users, the supported topology) always resolves the path.
fn refuse_unroutable_relay(
    stream: MeshStream,
    cluster: &ClusterCtx,
    carrier: CarrierKind,
    path: &str,
) {
    cluster.metrics.record_mesh_relay_rejected("no_route");
    warn!(
        ?carrier,
        path,
        "refusing a relayed carrier: it resolves to an empty route on this home, so every packet \
         would fail authentication — check that this home serves the edge's path and carrier \
         (cluster config must be symmetric)"
    );
    refuse_relay(stream, CloseReason::NoRoute);
}

/// Dispatches one relayed carrier into the matching accept path.
async fn serve_relayed(
    header: OpenHeader,
    mut stream: MeshStream,
    cluster: &ClusterCtx,
    services: &Services,
    routes: &RoutesSnapshot,
) -> Result<()> {
    // The carrier wrapping the mesh stream is built inside each arm: the
    // TCP/VLESS carriers use the byte-stream `MeshCarrier`, while SS-UDP uses
    // the datagram-framed `MeshUdpCarrier` (moving `stream` into the arm taken).
    let path: Arc<str> = Arc::from(header.path.as_str());

    // Admission comes first: resolve the route this carrier would authenticate
    // against, and refuse the stream outright if it holds no users. Doing it
    // here — before the active-relay gauge, the throttle registration and the
    // carrier — keeps an unroutable relay from ever counting as served.
    let Some(route) = resolve_relayed_route(routes, header.carrier, &path) else {
        // Unreachable in practice: an edge never builds a VlessUdp carrier.
        // VLESS-UDP rides the VlessTcp carrier — the edge forwards the VLESS
        // byte stream verbatim and the home's `run_vless_relay` parses the UDP
        // command from it. Kept as a defensive refusal (not a panic) in case a
        // peer sends a forged or mismatched-version header.
        warn!("unexpected VlessUdp mesh carrier (VLESS-UDP rides VlessTcp); refusing");
        refuse_relay(stream, CloseReason::Abort);
        bail!("VlessUdp mesh carrier is unreachable on the edge")
    };
    if route.is_empty() {
        refuse_unroutable_relay(stream, cluster, header.carrier, &path);
        return Ok(());
    }
    // Admitted. The ack is the first downlink byte, ahead of any carrier
    // payload: it releases the edge to upgrade its client carrier, knowing this
    // home will actually serve it.
    write_open_ack(&mut stream.send).await?;

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

    match (header.carrier, route) {
        (CarrierKind::SsTcp | CarrierKind::SsXhttp, RelayedRoute::Ss(route)) => {
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
        (CarrierKind::VlessTcp | CarrierKind::VlessXhttp, RelayedRoute::Vless(route)) => {
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
        (CarrierKind::SsUdp | CarrierKind::SsUdpXhttp, RelayedRoute::Ss(route)) => {
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
        // Unreachable: `resolve_relayed_route` pairs each carrier kind with the
        // route table it dispatches into, and `VlessUdp` was refused above.
        // Defensive (not a panic) rather than provable to the compiler.
        (carrier, _) => bail!("mesh carrier {carrier:?} has no matching relayed route table"),
    }
}

/// Upper bound on how long the home waits for the second-phase USER frame after
/// acking a v5 OPEN.
///
/// The accept loop's relay permit is held for the whole wait, so an acked peer
/// that then withholds the frame would otherwise pin a slot until the QUIC idle
/// timeout — minutes, and one slot per stream it opens. Deliberately the same
/// order as the registry's own `RESERVATION_WAIT` (5 s), which bounds the
/// neighbouring phase-2 `take_for_resume`. On expiry the stream is refused like
/// any other malformed setup.
const USER_FRAME_WAIT: Duration = Duration::from_secs(5);

/// Reads the second-phase USER frame off a v5 relay stream.
///
/// Bounded by construction: one length byte, then at most [`MAX_USER_LEN`]
/// bytes. A peer can never drive an unbounded read or allocation here, however
/// large a length it claims — the length is checked before the body is read.
async fn read_user_frame(recv: &mut RecvStream) -> Result<UserFrame> {
    let mut len = [0u8; 1];
    recv.read_exact(&mut len)
        .await
        .context("reading the mesh USER frame length")?;
    let claimed = len[0] as usize;
    if claimed > MAX_USER_LEN {
        bail!("mesh USER frame user name too long: {claimed}");
    }
    let mut frame = vec![0u8; 1 + claimed];
    frame[0] = len[0];
    recv.read_exact(&mut frame[1..])
        .await
        .context("reading the mesh USER frame")?;
    UserFrame::parse(&frame)
}

/// Serves one v5 relayed session: the two-phase resume hand-off.
///
/// Where [`serve_relayed`] admits a still-encrypted carrier and re-runs the
/// whole accept path against it, this path does none of that — the edge already
/// terminated the client's crypto, so the home is a pure session owner. There
/// is no route lookup (the path is a local matter of the edge), no decryptor and
/// no encryptor: the mesh carries application plaintext inside the QUIC/TLS
/// tunnel the peers already authenticated to each other with.
///
/// The two phases exist because the edge must decide what to echo in its `101`
/// before it can read the client's first encrypted frame, so it cannot name the
/// user in OPEN. Phase 1 therefore answers the narrower question "is there a
/// park under this id?" and phase 2 does the owner check `take_for_resume` has
/// always done, one round trip later. A refusal in phase 1 reaches the edge
/// *before* the client carrier is upgraded, which is what keeps a failed relay
/// from becoming a black hole.
async fn serve_relayed_v5(
    header: OpenHeaderV5,
    mut stream: MeshStream,
    cluster: &ClusterCtx,
    services: &Services,
) -> Result<()> {
    let session_id = SessionId::from_bytes(header.session_id);
    let registry = &services.orphan_registry;

    if header.framing == MeshFraming::Udp {
        // The home's plaintext SS-UDP path (NAT + park against SOCKS5-wrapped
        // datagrams) lands with the SS-UDP edge; until then no peer sends this
        // framing, so a stream carrying it is a peer running ahead of this
        // build. Refuse before consuming anything, and never take the park.
        cluster.metrics.record_mesh_relay_rejected("udp_unsupported");
        cluster.metrics.record_mesh_relay_outcome("miss");
        warn!("refusing a v5 SS-UDP relay: this home does not serve UDP framing yet");
        refuse_relay(stream, CloseReason::Abort);
        return Ok(());
    }

    // Phase 1: does a park exist under this id? The user is not known yet, so
    // this is deliberately the weaker check; an in-flight park counts as present
    // (see `OrphanRegistry::has_park`).
    if !registry.has_park(session_id) {
        cluster.metrics.record_mesh_relay_rejected("no_session");
        cluster.metrics.record_mesh_relay_outcome("miss");
        // An ordinary outcome — parks expire and are evicted — so this is not a
        // warning. The edge simply serves its client a fresh local session.
        debug!("no parked session for a relayed resume id; refusing the relay");
        refuse_relay(stream, CloseReason::NoSession);
        return Ok(());
    }
    // Admitted so far. The ack releases the edge to upgrade its client carrier
    // and echo continuity, and is the first downlink byte of the stream.
    if let Err(error) = write_open_ack(&mut stream.send).await {
        // The mesh stream broke during setup, before any park was consulted:
        // neither a hit nor a miss, but still one relay that entered this
        // handler — counted so the outcome series reconciles against the
        // streams actually served.
        cluster.metrics.record_mesh_relay_outcome("error");
        return Err(error);
    }

    // Phase 2: the user the edge authenticated, then the owner check. Bounded by
    // [`USER_FRAME_WAIT`]: an acked peer that never sends the frame would
    // otherwise hold its relay permit for the QUIC idle timeout.
    let user = match tokio::time::timeout(USER_FRAME_WAIT, read_user_frame(&mut stream.recv)).await
    {
        Ok(Ok(user)) => user,
        Ok(Err(error)) => {
            cluster.metrics.record_mesh_relay_rejected("bad_setup");
            cluster.metrics.record_mesh_relay_outcome("error");
            debug!(?error, "refusing a v5 relay whose USER frame is unusable");
            refuse_relay(stream, CloseReason::Abort);
            return Ok(());
        },
        Err(_elapsed) => {
            cluster.metrics.record_mesh_relay_rejected("bad_setup");
            cluster.metrics.record_mesh_relay_outcome("error");
            warn!(
                wait_secs = USER_FRAME_WAIT.as_secs(),
                "refusing a v5 relay: the peer was acked but never sent its USER frame",
            );
            refuse_relay(stream, CloseReason::Abort);
            return Ok(());
        },
    };
    let parked = match registry.take_for_resume(session_id, &user.user).await {
        ResumeOutcome::Hit(parked) => parked,
        ResumeOutcome::Miss(miss) => {
            let reason = match miss {
                // A park exists but under a different owner. Either a genuine
                // security event or the shared-user-namespace invariant broken
                // by config — worth a warning either way, and the user name is
                // an identifier, not a secret.
                ResumeMiss::OwnerMismatch => {
                    warn!(
                        user = %user.user,
                        "relayed resume rejected: the parked session belongs to another user — \
                         check that user names denote the same person on every cluster node",
                    );
                    "unknown_user"
                },
                // The park expired or was evicted between phase 1 and phase 2.
                _ => "no_session",
            };
            cluster.metrics.record_mesh_relay_rejected(reason);
            cluster.metrics.record_mesh_relay_outcome("miss");
            refuse_relay(stream, CloseReason::NoSession);
            return Ok(());
        },
    };
    let Parked::Tcp(parked) = parked else {
        // The OPEN's framing disagrees with what is actually parked under the
        // id — a forged or mismatched peer. Refuse rather than panic; the park
        // is already consumed, so the client loses continuity but nothing else.
        cluster.metrics.record_mesh_relay_rejected("framing_mismatch");
        cluster.metrics.record_mesh_relay_outcome("miss");
        warn!("relayed TCP framing does not match the parked session kind; aborting the relay");
        refuse_relay(stream, CloseReason::Abort);
        return Ok(());
    };
    cluster.metrics.record_mesh_relay_outcome("hit");
    // Count this relay as active for its whole lifetime; the guard drops on
    // return, including every early bail inside the splice.
    let _relay_active = cluster.metrics.open_mesh_relay();
    splice_plaintext_tcp(stream, parked, &header, session_id, cluster, registry).await
}

/// A failed half of a v5 splice: what the edge must see, and whether the parked
/// upstream survived it.
struct SpliceFault {
    /// Reset code sent on the mesh stream before the splice returns. Without it
    /// quinn's `Drop for SendStream` finishes the stream, so the edge would read
    /// a stalled home or a broken upstream as a clean close and seal a truncated
    /// response to its client.
    reset: CloseReason,
    /// Whether the parked upstream is still healthy — i.e. whether the session
    /// is worth re-parking for a later carrier.
    upstream_healthy: bool,
    error: anyhow::Error,
}

impl SpliceFault {
    /// The mesh peer failed (read or write): the upstream is untouched, so the
    /// session is re-parked exactly as if the client had simply gone away.
    fn mesh(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Abort,
            upstream_healthy: true,
            error,
        }
    }

    /// The upstream socket failed: a later resume would reattach to a dead
    /// socket, so nothing is parked.
    fn upstream(error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Abort,
            upstream_healthy: false,
            error,
        }
    }

    /// A single write stalled past the health budget. `upstream_healthy` says
    /// which side stalled: a stalled mesh write means a wedged edge (the parked
    /// upstream is fine), a stalled upstream write means the socket itself is
    /// not draining. The edge sees [`CloseReason::Budget`] either way, mirroring
    /// what the edge pump signals to the home.
    fn stalled(upstream_healthy: bool, error: anyhow::Error) -> Self {
        Self {
            reset: CloseReason::Budget,
            upstream_healthy,
            error,
        }
    }

    fn into_end(self) -> SpliceEnd {
        SpliceEnd {
            upstream_healthy: self.upstream_healthy,
            reset: Some(self.reset),
            error: Some(self.error),
        }
    }
}

/// How a v5 splice ended, once both halves are back in the caller's hands.
struct SpliceEnd {
    /// Whether to re-park the upstream for the next carrier.
    upstream_healthy: bool,
    /// `Some` on every failure path; `None` on the two graceful ends (the edge
    /// finished the mesh stream, or the upstream EOF'd).
    reset: Option<CloseReason>,
    error: Option<anyhow::Error>,
}

/// Splices a relayed plaintext stream onto a parked TCP upstream.
///
/// Simpler than the v4 path beside it: no decryptor, no encryptor, no route
/// context — just the unacked replay suffix followed by a bidirectional pump.
/// The ring already holds **plaintext** keyed by plaintext offsets, so the
/// suffix goes out as-is and the edge seals it under its own client key.
///
/// Health budget: `cluster.relay_budget` bounds a single write in each
/// direction, so a peer (or an upstream) that stops draining tears the relay
/// down instead of pinning the parked socket forever. It measures progress, not
/// RTT — an idle relay blocks on a read, never on a write.
///
/// Both pumps borrow their halves rather than consuming them, so whichever side
/// ends first this function gets the halves back. That is what makes the two
/// obligations below possible:
///
/// * **Failures never look graceful.** Every error arm resets the mesh stream
///   ([`CloseReason::Budget`] for a stalled write, [`CloseReason::Abort`]
///   otherwise) before returning. Dropping the send half instead would `finish`
///   it, and the edge would read a stalled home or a broken upstream as a clean
///   upstream close — sealing a truncated response to its client as complete.
/// * **The session is re-parked.** When the client side goes away while the
///   upstream is healthy, the upstream halves go back into the registry under
///   the same id, mirroring the direct path's `try_park_on_drop`. Without it a
///   v5 session would survive exactly one carrier switch.
async fn splice_plaintext_tcp(
    stream: MeshStream,
    parked: ParkedTcp,
    header: &OpenHeaderV5,
    session_id: SessionId,
    cluster: &ClusterCtx,
    registry: &OrphanRegistry,
) -> Result<()> {
    let MeshStream { mut send, mut recv } = stream;
    // Every field is kept: the plaintext splice itself needs only the socket
    // halves and the ring, but a re-park has to hand the whole bundle back to
    // the registry with the same field semantics the direct path parks with.
    // The user is already authenticated (by the edge, attested in the USER
    // frame) and the owner check is done, so neither the identity nor the SS
    // user key does any work *here* — `owner` still keys the park and
    // `protocol_context` still guards a later cross-protocol resume.
    let ParkedTcp {
        mut upstream_writer,
        mut upstream_reader,
        target_display,
        owner,
        protocol_context,
        // Per-user byte accounting stays with the node that terminates the
        // client session, i.e. the edge; the home counts this traffic on its
        // `role="home"` mesh counters below.
        user_counters,
        upstream_guard,
        upstream_bytes_acked,
        downlink_ring,
    } = parked;

    let up_bytes = cluster.metrics.mesh_bytes_counter("home", "up", "tcp");
    let down_bytes = cluster.metrics.mesh_bytes_counter("home", "down", "tcp");
    let budget = cluster.relay_budget;

    // Byte-continuity: everything the session emitted past the offset the client
    // acknowledged goes out first, ahead of any fresh upstream byte, so the
    // client's stream has no gap and no duplicate across the carrier switch.
    if header.symmetric_replay
        && let Some(ring) = &downlink_ring
    {
        let outcome = ring.lock().replay_from(header.client_down_acked);
        match outcome {
            ReplayOutcome::Available(bytes) if !bytes.is_empty() => {
                send.write_all(&bytes)
                    .await
                    .context("replaying the downlink suffix over the mesh")?;
                down_bytes.increment(bytes.len() as u64);
            },
            // Nothing outstanding: the client observed everything sent.
            ReplayOutcome::Available(_) => {},
            // Eviction rolled past the requested offset, or the client claims
            // more than was ever sent. Continuity is lost for the gap; the
            // session still runs from here.
            //
            // TODO: the v5 OPEN ack carries no flag for this, so unlike the
            // direct path (which sets REPLAY_TRUNCATED in its "ORDR" frame) the
            // home cannot yet tell the edge to fail the client fast, as
            // `docs/SESSION-RESUMPTION.md` requires. Until that protocol field
            // exists the condition is at least observable on the same counter
            // the direct path feeds.
            other => {
                cluster.metrics.record_orphan_downlink_replay_truncated("tcp");
                debug!(
                    ?other,
                    target = %target_display,
                    "no replayable downlink suffix for a relayed resume; the client is not yet \
                     told about the gap",
                );
            },
        }
    }

    let end = {
        // Reborrows, so the pumps own references and the halves come back to
        // this scope when the pumps drop.
        let recv = &mut recv;
        let send = &mut send;
        let writer = &mut upstream_writer;
        let reader = &mut upstream_reader;
        let acked = &upstream_bytes_acked;
        let ring = &downlink_ring;

        // Uplink: mesh → parked upstream. The ONLY writer to the upstream socket.
        let uplink = async move {
            loop {
                let chunk = match recv
                    .read_chunk(MESH_HOME_SPLICE_CHUNK, true)
                    .await
                    .context("relayed uplink read from the mesh")
                {
                    Ok(Some(chunk)) => chunk,
                    // The edge finished the stream: the client carrier is gone.
                    // The upstream is deliberately left open — the caller
                    // re-parks it for the next carrier, and a half-close would
                    // make that park useless. The non-park path shuts it down.
                    Ok(None) => return Ok(()),
                    Err(error) => return Err(SpliceFault::mesh(error)),
                };
                let len = chunk.bytes.len();
                match tokio::time::timeout(budget, writer.write_all(&chunk.bytes)).await {
                    Ok(Ok(())) => {},
                    Ok(Err(error)) => {
                        return Err(SpliceFault::upstream(
                            anyhow::Error::new(error)
                                .context("relayed uplink write to the upstream"),
                        ));
                    },
                    Err(_elapsed) => {
                        return Err(SpliceFault::stalled(
                            false,
                            anyhow::anyhow!("relayed uplink stalled past the health budget"),
                        ));
                    },
                }
                up_bytes.increment(len as u64);
                // Keeps the Ack-Prefix counter monotonic across this reattach,
                // the same guarantee the direct relay gives.
                acked.fetch_add(len as u64, Ordering::Relaxed);
            }
        };

        // Downlink: parked upstream → mesh. The ONLY writer to the mesh stream.
        // One buffer for the relay's lifetime, bounded by MESH_HOME_SPLICE_CHUNK.
        let downlink = async move {
            let mut buf = vec![0u8; MESH_HOME_SPLICE_CHUNK];
            loop {
                let len = match reader
                    .read(&mut buf)
                    .await
                    .context("relayed downlink read from the upstream")
                {
                    Ok(len) => len,
                    Err(error) => return Err(SpliceFault::upstream(error)),
                };
                if len == 0 {
                    // Upstream EOF — the one case where a graceful FIN is the
                    // truth, so the edge can seal a complete response.
                    let _ = send.finish();
                    return Ok(());
                }
                // Capture plaintext into the ring before it leaves the home,
                // exactly as the direct relay does — so a later park under this
                // id can still replay the suffix from a consistent offset.
                if let Some(ring) = ring {
                    ring.lock().push(&buf[..len]);
                }
                match tokio::time::timeout(budget, send.write_all(&buf[..len])).await {
                    Ok(Ok(())) => {},
                    Ok(Err(error)) => {
                        return Err(SpliceFault::mesh(
                            anyhow::Error::new(error).context("relayed downlink write to the mesh"),
                        ));
                    },
                    Err(_elapsed) => {
                        return Err(SpliceFault::stalled(
                            true,
                            anyhow::anyhow!("relayed downlink stalled past the health budget"),
                        ));
                    },
                }
                down_bytes.increment(len as u64);
            }
        };

        tokio::pin!(uplink, downlink);
        let mut upstream_eof = false;
        loop {
            tokio::select! {
                result = &mut uplink => break match result {
                    Ok(()) => SpliceEnd {
                        upstream_healthy: !upstream_eof,
                        reset: None,
                        error: None,
                    },
                    Err(fault) => {
                        let mut end = fault.into_end();
                        // An upstream that already EOF'd is never worth parking,
                        // whatever broke afterwards — a resume would reattach to
                        // a socket with nothing left to read.
                        end.upstream_healthy &= !upstream_eof;
                        end
                    },
                },
                result = &mut downlink, if !upstream_eof => match result {
                    // The upstream is done, but the edge may still be uploading
                    // a request body, so the uplink keeps running until it ends
                    // too — the same shape the previous join had.
                    Ok(()) => upstream_eof = true,
                    Err(fault) => break fault.into_end(),
                },
            }
        }
    };

    match end.reset {
        Some(reason) => {
            let _ = send.reset(VarInt::from_u32(reason.code()));
        },
        // Graceful end. A no-op when the downlink pump already finished the
        // stream on upstream EOF.
        None => {
            let _ = send.finish();
        },
    }

    if end.upstream_healthy && registry.enabled() {
        // Mirror of the direct path's `transport::tcp::try_park_on_drop`: the
        // client side went away while the upstream is healthy, so the whole
        // bundle goes back under the same id for the next carrier to resume.
        //
        // No `reserve_park` is taken (the direct path needs one only because it
        // awaits a reader harvest between deciding to park and committing): here
        // both halves are already in hand and `park` commits synchronously, so
        // there is no window for a racing resume to miss.
        debug!(
            user = %owner,
            target = %target_display,
            "re-parking a relayed tcp upstream after the mesh carrier ended",
        );
        registry.park(
            session_id,
            Parked::Tcp(ParkedTcp {
                upstream_writer,
                upstream_reader,
                target_display,
                owner,
                protocol_context,
                user_counters,
                upstream_guard,
                upstream_bytes_acked,
                downlink_ring,
            }),
        );
    } else {
        // Nothing worth parking (the upstream EOF'd or failed, or resumption is
        // off): half-close so the target sees the end of the request body. The
        // upstream guard drops with this scope, releasing the gauge.
        let _ = upstream_writer.shutdown().await;
    }

    match end.error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "tests/mesh_relay.rs"]
mod tests;
