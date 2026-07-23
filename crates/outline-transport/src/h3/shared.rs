// Connection infrastructure for the HTTP/3 WebSocket transport.
//
// Owns the QUIC/TLS configs, shared endpoints, per-key connect locks,
// shared-connection cache, and all connect / gc logic.  The stream adapter
// types (`H3WsStream`, `H3ConnectionGuard`) and the message-conversion helpers
// live in the parent module (`mod.rs`) because they are the public API
// consumed by `ws_stream.rs`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use http::{Method, Request};
use once_cell::sync::OnceCell;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::info;
use url::Url;

use crate::shared_cache::{
    ConnCloseLog, SharedConnectionRegistry, classify_by_substrings, log_conn_close,
};
use crate::{AbortOnDrop, DnsCache, TransportStream, bind_addr_for, bind_udp_socket};

use crate::resumption::NegotiatedResume;

use super::vendored::{self, H3RequestStreamHandle, H3SendRequestHandle};
use super::{H3ConnectionGuard, H3WsStream, websocket_h3_target_uri, websocket_path};

// Upper bound for opening a new H3 WebSocket stream on top of an already
// established QUIC connection.  Without this bound, a silently-broken shared
// QUIC connection (network dropped but quinn has not yet hit its 120s idle
// timeout) makes every new SOCKS TCP session hang indefinitely on the CONNECT
// request instead of producing an error that would invalidate the shared
// connection and trigger failover through `report_runtime_failure`.  The
// handshake itself is already complete at this point; a generous budget of a
// few seconds is plenty for a healthy path and keeps the worst-case recovery
// latency bounded.
const OPEN_WEBSOCKET_TIMEOUT: Duration = Duration::from_secs(7);

// Upper bound for establishing a fresh HTTP/3 connection (QUIC handshake +
// HTTP/3 handshake).  Without this bound, a server black hole would let the
// QUIC handshake stall for up to `max_idle_timeout` (120s), which masks
// failover in exactly the same way as the shared-connection stalls do.
// 10 seconds matches the bound used for fresh H2 and H1 handshakes.
const FRESH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── Connection key ────────────────────────────────────────────────────────────

// The cache key is intentionally based on the *hostname* and port rather than
// the resolved IP address.  Using the IP address would create a new cache entry
// on every DNS rotation (round-robin CDN, failover, etc.), leaving the old
// QUIC connection alive in the map forever because `is_open()` stays `true`
// until the server eventually drops the idle connection.  A hostname-based key
// means the DNS answer changing keeps the old connection until it fails
// naturally, at which point a fresh connection is made to the (now re-resolved)
// new address.
//
// The key additionally carries a `slot` (0..`H3_CARRIER_MAX`) so a logical
// server is served by several *independent* shared QUIC connections rather than
// a single one. New dials are placed by `choose_slot` on the least-loaded
// carrier under a per-carrier cap, keeping at least `H3_CARRIER_MIN` carriers
// alive for isolation. Multiplexing the whole host onto one shared connection
// means any connection-level close (server-side `H3_INTERNAL_ERROR`, a
// qpack/protocol fault, an idle timeout) tears down *every* flow to that server
// at once — including long-lived SSE streams. Spreading flows across carriers
// bounds that blast radius to the flows that happen to sit on the collapsing
// carrier, and the reduced per-carrier stream concurrency also shrinks the race
// window that triggers the collapse in the first place.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct H3ConnectionKey {
    base: crate::shared_cache::ConnectionKey,
    slot: u8,
}

impl H3ConnectionKey {
    pub(super) fn with_slot(
        server_name: &str,
        server_port: u16,
        fwmark: Option<u32>,
        slot: u8,
    ) -> Self {
        Self {
            base: crate::shared_cache::ConnectionKey::new(server_name, server_port, fwmark),
            slot,
        }
    }
}

// Carrier-pool policy. Flows to a logical server are spread across several
// independent shared QUIC connections ("carriers"), each a distinct `slot` in
// the cache key, so a single connection-level collapse only takes down the
// streams on one carrier instead of every flow at once.
//
//  * MIN — always keep at least this many carriers once there is traffic, so
//    even a lightly-loaded host (a handful of flows) isolates a long-lived SSE
//    stream from the bulk of the traffic. Without a floor, a low flow count
//    would pack everything back onto one carrier and re-expose the SSE.
//  * CAP — soft ceiling on live streams per carrier. Past it the picker opens
//    another carrier, bounding the absolute blast radius under heavy load and
//    keeping per-carrier stream concurrency (hence the collapse race window)
//    small.
//  * MAX — hard ceiling on carriers per host. Once every slot is populated and
//    full, streams pack beyond CAP (soft) rather than opening an unbounded
//    number of QUIC connections / keep-alive PINGs.
const H3_CARRIER_MIN: u8 = 4;
const H3_CARRIER_CAP: u64 = 32;
const H3_CARRIER_MAX: u8 = 16;

/// Pure carrier-selection policy, factored out of `pick_h3_carrier_slot` so it
/// can be unit-tested without a live registry.
///
/// `loads[i]` is `Some(active_streams)` for the carrier in slot `i` when it is
/// open, or `None` when that slot is empty (or holds a dead carrier the caller
/// will re-dial). The returned slot index is always `< loads.len()`.
///
/// Policy, in order:
///   1. Below the MIN carrier floor → open the first empty slot for isolation.
///   2. Otherwise pack onto the least-loaded open carrier under CAP.
///   3. If every open carrier is at CAP → open the first empty slot (grow).
///   4. If none is empty either (MAX carriers, all full) → soft-overflow onto
///      the least-loaded carrier overall.
///
/// Ties resolve to the lowest slot index, which makes selection deterministic
/// and self-balancing: successive dials fill slot 0, then 1, … up to the floor,
/// then keep the pool evenly loaded.
fn choose_slot(loads: &[Option<u64>], min: u8, cap: u64) -> u8 {
    let mut populated: u8 = 0;
    let mut first_empty: Option<u8> = None;
    let mut best_under_cap: Option<(u8, u64)> = None;
    let mut least_overall: Option<(u8, u64)> = None;

    for (slot, load) in loads.iter().enumerate() {
        let slot = slot as u8;
        match *load {
            Some(active) => {
                populated += 1;
                if least_overall.is_none_or(|(_, a)| active < a) {
                    least_overall = Some((slot, active));
                }
                if active < cap && best_under_cap.is_none_or(|(_, a)| active < a) {
                    best_under_cap = Some((slot, active));
                }
            },
            None if first_empty.is_none() => first_empty = Some(slot),
            None => {},
        }
    }

    if populated < min
        && let Some(empty) = first_empty
    {
        return empty;
    }
    if let Some((slot, _)) = best_under_cap {
        return slot;
    }
    if let Some(empty) = first_empty {
        return empty;
    }
    least_overall.map_or(0, |(slot, _)| slot)
}

/// Inspect every carrier slot for `(server_name, server_port, fwmark)` and pick
/// the one a fresh dial should target, per [`choose_slot`]. Read-only: uses
/// `peek` so probing the pool never evicts a stale entry.
async fn pick_h3_carrier_slot(server_name: &str, server_port: u16, fwmark: Option<u32>) -> u8 {
    let mut loads: Vec<Option<u64>> = Vec::with_capacity(H3_CARRIER_MAX as usize);
    for slot in 0..H3_CARRIER_MAX {
        let key = H3ConnectionKey::with_slot(server_name, server_port, fwmark, slot);
        let load = match h3_registry().peek(&key).await {
            Some(conn) if conn.is_open() => Some(conn.active()),
            _ => None,
        };
        loads.push(load);
    }
    choose_slot(&loads, H3_CARRIER_MIN, H3_CARRIER_CAP)
}

// ── Shared connection ─────────────────────────────────────────────────────────

pub(super) struct SharedH3Connection {
    pub(super) id: u64,
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    // Kept alive to prevent the h3 driver from initiating graceful shutdown
    // (H3_NO_ERROR) prematurely. The h3 layer treats the last SendRequest
    // being dropped as a signal that no more requests will be made.
    send_request: Mutex<H3SendRequestHandle>,
    /// Soft-close flag: set to `true` by `open_websocket` on timeout so no
    /// new streams are opened, but existing streams continue to work
    /// undisturbed.  Using `connection.close()` was too aggressive — it kills
    /// ALL active H3 streams on the shared connection, causing a cascade of
    /// reconnects and rapid FD growth.
    closed: AtomicBool,
    // conn_life diagnostics: counts every WS stream opened on this connection
    // (observed at close by the driver task) to correlate session_death bursts
    // with a single underlying connection's death.
    streams_opened: Arc<AtomicU64>,
    // Live (not-yet-dropped) WS streams currently multiplexed on this carrier.
    // Unlike `streams_opened` (monotonic, diagnostic) this rises and falls with
    // real usage: `CarrierActiveGuard` increments it when a stream is handed out
    // and decrements it on drop. The slot-picker reads it to keep each carrier
    // under `H3_CARRIER_CAP`, which both bounds the reconnect blast radius and
    // caps the per-carrier stream concurrency that opens the collapse race.
    active_streams: Arc<AtomicU64>,
    _connection_guard: H3ConnectionGuard,
    _driver_task: AbortOnDrop,
}

/// RAII counter for the live streams on a single carrier. Cloned off the
/// carrier's `active_streams` when a `H3WsStream` is created and dropped with
/// it, so the count always reflects the streams actually alive on that carrier.
pub(super) struct CarrierActiveGuard(Arc<AtomicU64>);

impl CarrierActiveGuard {
    fn new(active_streams: Arc<AtomicU64>) -> Self {
        active_streams.fetch_add(1, Ordering::Relaxed);
        Self(active_streams)
    }
}

impl Drop for CarrierActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl SharedH3Connection {
    pub(super) fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.connection.close_reason().is_none()
    }

    /// Number of live WS streams currently multiplexed on this carrier.
    pub(super) fn active(&self) -> u64 {
        self.active_streams.load(Ordering::Relaxed)
    }

    pub(super) async fn open_websocket(
        self: &Arc<Self>,
        server_name: &str,
        server_port: u16,
        path: &str,
        resume: &crate::dial_plan::DialResumeOptions,
        profile: Option<&'static crate::fingerprint_profile::Profile>,
    ) -> Result<(H3WsStream, NegotiatedResume)> {
        match self
            .open_websocket_inner(server_name, server_port, path, resume, profile)
            .await
        {
            Ok(ws) => Ok(ws),
            Err(error) => {
                // Any failure opening a new CONNECT stream on an already-cached
                // shared QUIC connection is a strong signal the connection is
                // sick (send timeout, response timeout, non-2xx status, etc.).
                // Soft-close so concurrent callers racing to open another
                // stream skip this entry in `is_open()` and fall through to
                // the cache-invalidation path.
                self.closed.store(true, Ordering::Relaxed);
                Err(error)
            },
        }
    }

    async fn open_websocket_inner(
        self: &Arc<Self>,
        server_name: &str,
        server_port: u16,
        path: &str,
        resume: &crate::dial_plan::DialResumeOptions,
        profile: Option<&'static crate::fingerprint_profile::Profile>,
    ) -> Result<(H3WsStream, NegotiatedResume)> {
        if !self.is_open() {
            bail!("shared h3 connection is already closed");
        }

        let request_builder = Request::builder()
            .method(Method::CONNECT)
            .uri(websocket_h3_target_uri(server_name, server_port, path)?)
            .extension(vendored::websocket_protocol())
            .header("sec-websocket-version", "13");
        let mut request: Request<()> =
            request_builder.body(()).expect("request builder never fails");
        crate::resumption::apply_resume_request_headers(resume, request.headers_mut());
        if let Some(profile) = profile {
            crate::fingerprint_profile::apply(
                profile,
                request.headers_mut(),
                crate::fingerprint_profile::SecFetchPreset::WebsocketUpgrade,
            );
        }

        let mut stream: H3RequestStreamHandle = timeout(OPEN_WEBSOCKET_TIMEOUT, async {
            let mut send_request = self.send_request.lock().await;
            send_request
                .send_request(request)
                .await
                .context("failed to send HTTP/3 websocket CONNECT request")
        })
        .await
        .map_err(|_| {
            anyhow!(
                "HTTP/3 websocket CONNECT request timed out after {}s on shared connection",
                OPEN_WEBSOCKET_TIMEOUT.as_secs()
            )
        })??;

        let response = timeout(OPEN_WEBSOCKET_TIMEOUT, stream.recv_response())
            .await
            .map_err(|_| {
                anyhow!(
                    "HTTP/3 websocket CONNECT response timed out after {}s on shared connection",
                    OPEN_WEBSOCKET_TIMEOUT.as_secs()
                )
            })?
            .context("failed to receive HTTP/3 websocket response")?;
        if !response.status().is_success() {
            bail!("HTTP/3 websocket CONNECT failed with status {}", response.status());
        }
        let negotiated = crate::resumption::parse_resume_response_echo(resume, response.headers());

        self.streams_opened.fetch_add(1, Ordering::Relaxed);
        Ok((
            H3WsStream {
                inner: vendored::client_ws_stream(stream, 90_000),
                _active: CarrierActiveGuard::new(Arc::clone(&self.active_streams)),
                _shared_connection: Arc::clone(self),
            },
            negotiated,
        ))
    }
}

impl crate::SharedConnectionHealth for SharedH3Connection {
    fn is_open(&self) -> bool {
        self.is_open()
    }

    fn conn_id(&self) -> u64 {
        self.id
    }

    fn mode(&self) -> &'static str {
        "h3"
    }
}

impl crate::shared_cache::CachedEntry for SharedH3Connection {
    fn conn_id(&self) -> u64 {
        self.id
    }

    fn is_open(&self) -> bool {
        self.is_open()
    }
}

// The H3 QUIC/TLS client config lives in `crate::quic` (`h3_quic_client_config`),
// shared with the XHTTP-over-H3 carrier and keyed by dial fingerprint so the H3
// ClientHello mimics the same browser family as the WS / XHTTP carriers, with
// the same per-process keep-alive / idle jitter (8–12 s / 28–35 s). The jitter
// range keeps the ~30 s idle budget that tears a silently-dropped QUIC path off
// consumer-router conntrack, while QUIC PING (8–12 s) keeps NAT mappings fresh.

// ── Shared endpoints ──────────────────────────────────────────────────────────

// One UDP socket per address family, shared across all H3 connections that do
// not require a per-socket fwmark. Sharing the endpoint eliminates the "N
// warm-standby connections = N UDP sockets" resource explosion.
static H3_CLIENT_ENDPOINT_V4: OnceCell<quinn::Endpoint> = OnceCell::new();
static H3_CLIENT_ENDPOINT_V6: OnceCell<quinn::Endpoint> = OnceCell::new();

/// Endpoint for one H3 dial, shared by the WS-over-H3 carrier and the
/// XHTTP-over-H3 one.
///
/// For fwmark connections the socket must be bound with the mark set before
/// connect, so each dial needs its own UDP socket and endpoint. Every other
/// dial reuses the shared per-address-family endpoint, so N connections share
/// a single UDP socket instead of opening N.
pub(crate) fn client_endpoint(
    bind_addr: std::net::SocketAddr,
    fwmark: Option<u32>,
) -> Result<quinn::Endpoint> {
    if fwmark.is_some() {
        let socket = bind_udp_socket(bind_addr, fwmark)?;
        return quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| format!("failed to bind QUIC client endpoint on {bind_addr}"));
    }
    get_or_init_shared_h3_endpoint(bind_addr)
}

fn get_or_init_shared_h3_endpoint(bind_addr: std::net::SocketAddr) -> Result<quinn::Endpoint> {
    // Cross-repo integration tests run each `#[tokio::test]` in its
    // own runtime; the shared endpoint's driver task is spawned on
    // whichever runtime first hit the cache, so it dies the moment
    // that test ends. Bypass the cache in test mode and bind a fresh
    // endpoint per dial — production behaviour is unchanged.
    if crate::tls::test_mode_active() {
        let socket = bind_udp_socket(bind_addr, None)?;
        return quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| format!("failed to bind H3 QUIC client endpoint on {bind_addr}"));
    }
    let cell = if bind_addr.is_ipv4() {
        &H3_CLIENT_ENDPOINT_V4
    } else {
        &H3_CLIENT_ENDPOINT_V6
    };
    let endpoint = cell.get_or_try_init(|| {
        let socket = bind_udp_socket(bind_addr, None)?;
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .with_context(|| format!("failed to bind shared QUIC client endpoint on {bind_addr}"))
    })?;
    Ok(endpoint.clone())
}

// ── Shared-connection cache ───────────────────────────────────────────────────

// Global registry holding the shared-connection map, the per-key reconnect
// locks, and the connection-id counter. Mirrors the flow-table pattern in
// `tun_tcp` / `tun_udp`: hot-path lookups take only a brief read-lock on the
// inner map. The registry abstraction lives in `shared_cache` and is shared
// with H2.
static H3_REGISTRY: OnceLock<SharedConnectionRegistry<H3ConnectionKey, SharedH3Connection>> =
    OnceLock::new();

fn h3_registry() -> &'static SharedConnectionRegistry<H3ConnectionKey, SharedH3Connection> {
    H3_REGISTRY.get_or_init(SharedConnectionRegistry::new)
}

// ── H3Dialer ──────────────────────────────────────────────────────────────────

struct H3Dialer {
    /// Resume negotiation the caller wants on this open. Captured at
    /// dialer construction so the trait `open_on` method can stay
    /// signature-stable while threading the request through.
    resume: crate::dial_plan::DialResumeOptions,
    /// Browser identity to mix into the CONNECT request headers, or
    /// `None` when fingerprint diversification is disabled. Threaded
    /// alongside `resume` for the same reason — the trait signature
    /// stays unchanged.
    profile: Option<&'static crate::fingerprint_profile::Profile>,
    /// Carrier slot (0..`H3_CARRIER_MAX`) this dial targets so its flows land on
    /// one of the independent shared QUIC connections rather than all sharing a
    /// single carrier. Chosen once per `connect_websocket_h3` call by
    /// `pick_h3_carrier_slot` and folded into every key this dialer makes.
    slot: u8,
}

impl crate::shared_dial::WsDialer for H3Dialer {
    type Key = H3ConnectionKey;
    type Conn = SharedH3Connection;

    fn registry(&self) -> &'static SharedConnectionRegistry<H3ConnectionKey, SharedH3Connection> {
        h3_registry()
    }

    fn metric_label(&self) -> &'static str {
        "h3"
    }

    fn multi_address_failover_enabled(&self) -> bool {
        true
    }

    fn make_key(
        &self,
        server_name: &str,
        server_port: u16,
        fwmark: Option<u32>,
    ) -> H3ConnectionKey {
        H3ConnectionKey::with_slot(server_name, server_port, fwmark, self.slot)
    }

    async fn establish(
        &self,
        addr: SocketAddr,
        server_name: &str,
        fwmark: Option<u32>,
        cache_key: Option<H3ConnectionKey>,
    ) -> Result<Arc<SharedH3Connection>> {
        Ok(Arc::new(connect_h3_connection(addr, server_name, fwmark, cache_key).await?))
    }

    async fn open_on(
        &self,
        conn: &Arc<SharedH3Connection>,
        server_name: &str,
        server_port: u16,
        path: &str,
    ) -> Result<TransportStream> {
        let (ws, negotiated) = conn
            .open_websocket(server_name, server_port, path, &self.resume, self.profile)
            .await?;
        Ok(TransportStream::H3 {
            inner: ws,
            issued_session_id: negotiated.issued_session_id,
            downgraded_from: None,
            ack_prefix_advertised_by_server: negotiated.ack_prefix_advertised_by_server,
            symmetric_replay_advertised_by_server: negotiated.symmetric_replay_advertised_by_server,
        })
    }
}

// ── Connect ───────────────────────────────────────────────────────────────────

pub(crate) async fn connect_websocket_h3(
    cache: &DnsCache,
    url: &Url,
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    resume: crate::dial_plan::DialResumeOptions,
) -> Result<TransportStream> {
    if url.scheme() != "wss" {
        bail!("h3 websocket transport currently requires wss:// URLs");
    }

    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL is missing port"))?;
    let path = websocket_path(url);
    let profile = crate::fingerprint_profile::select(url);
    let slot = pick_h3_carrier_slot(host, port, fwmark).await;
    let dialer = H3Dialer { resume, profile, slot };

    if crate::shared_cache::should_reuse_connection(source) {
        // DNS resolution is deferred to the slow path inside connect_ws_reused
        // so the cache key stays hostname-based and is not affected by DNS rotation.
        crate::shared_dial::connect_ws_reused(
            &dialer, cache, host, port, &path, fwmark, ipv6_first, source,
        )
        .await
    } else {
        // Probes never share connections; resolve DNS upfront and try each address.
        crate::shared_dial::connect_ws_probe(
            &dialer, cache, host, port, &path, fwmark, ipv6_first, source,
        )
        .await
    }
}

async fn connect_h3_connection(
    server_addr: SocketAddr,
    server_name: &str,
    fwmark: Option<u32>,
    cache_key: Option<H3ConnectionKey>,
) -> Result<SharedH3Connection> {
    let bind_addr = bind_addr_for(server_addr);
    let client_config = crate::quic::h3_quic_client_config();

    // Own endpoint for fwmark dials, shared per-address-family endpoint
    // otherwise — see [`client_endpoint`].
    let endpoint = client_endpoint(bind_addr, fwmark)?;

    let connecting = endpoint
        .connect_with(client_config, server_addr, server_name)
        .with_context(|| format!("failed to initiate QUIC connection to {server_addr}"))?;
    let (connection_handle, mut driver, send_request) = timeout(FRESH_CONNECT_TIMEOUT, async {
        let connection = connecting
            .await
            .with_context(|| format!("QUIC handshake failed for {server_addr}"))?;
        let connection_handle = connection.clone();
        let (driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .context("HTTP/3 handshake failed")?;
        Ok::<_, anyhow::Error>((connection_handle, driver, send_request))
    })
    .await
    .map_err(|_| {
        anyhow!(
            "HTTP/3 fresh connect timed out after {}s to {server_addr}",
            FRESH_CONNECT_TIMEOUT.as_secs()
        )
    })??;

    let id = h3_registry().next_id();
    let streams_opened = Arc::new(AtomicU64::new(0));
    let streams_opened_driver = Arc::clone(&streams_opened);
    let opened_at = Instant::now();
    let peer = server_addr.to_string();
    let peer_for_driver = peer.clone();
    info!(
        target: "outline_transport::conn_life",
        id, peer = %peer, mode = "h3", "h3 connection opened"
    );
    let driver_task = AbortOnDrop::new(tokio::spawn(async move {
        let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        if let Some(cache_key) = cache_key {
            h3_registry().invalidate_if_current(&cache_key, id).await;
        }
        let err_text = err.to_string();
        let class = classify_h3_close(&err_text);
        let expected = is_expected_h3_close(&err_text);
        let fields = ConnCloseLog {
            id,
            peer: &peer_for_driver,
            mode: "h3",
            age_secs: opened_at.elapsed().as_secs(),
            streams: streams_opened_driver.load(Ordering::Relaxed),
        };
        log_conn_close(fields, Some(&err_text), class, expected);
    }));

    Ok(SharedH3Connection {
        id,
        endpoint,
        connection: connection_handle.clone(),
        send_request: Mutex::new(send_request),
        closed: AtomicBool::new(false),
        streams_opened,
        active_streams: Arc::new(AtomicU64::new(0)),
        _connection_guard: H3ConnectionGuard(connection_handle),
        _driver_task: driver_task,
    })
}

fn classify_h3_close(err: &str) -> &'static str {
    // H3 close strings are produced by h3/quinn and retain mixed case; match
    // as-is rather than normalizing so categories remain precise (e.g.
    // `Timeout` is quinn's idle-timeout enum variant).
    classify_by_substrings(
        err,
        &[
            (&["H3_NO_ERROR"], "h3_no_error"),
            (&["H3_INTERNAL_ERROR"], "h3_internal"),
            (&["H3_REQUEST_REJECTED"], "h3_rejected"),
            (&["H3_CONNECT_ERROR"], "h3_connect_error"),
            (&["ApplicationClose"], "app_close"),
            (&["Timeout", "timed out"], "timeout"),
            (&["closed by client", "Connection closed by client"], "local_close"),
            (&["reset", "Reset"], "rst"),
            (&["tls", "TLS", "certificate"], "tls"),
        ],
        "other",
    )
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

/// Remove all cache entries whose shared connection is no longer open.
/// Called periodically from the warm-standby maintenance loop so dead entries
/// do not linger indefinitely when no new request re-checks their key (e.g.
/// after DNS rotation changes the resolved address for a server name).
pub(crate) async fn gc_shared_h3_connections() {
    h3_registry().gc().await;
}

fn is_expected_h3_close(err: &str) -> bool {
    err.contains("H3_NO_ERROR")
        || err.contains("Connection closed by client")
        || err.contains("connection closed by client")
        // H3 application-level closes from the server (e.g. H3_INTERNAL_ERROR
        // when the backend crashes under load). These are already reported as
        // runtime uplink failures via closed_cleanly=false in the flow reader;
        // logging them as ERROR here would just add noise.
        || err.contains("H3_INTERNAL_ERROR")
        || err.contains("H3_REQUEST_REJECTED")
        || err.contains("H3_CONNECT_ERROR")
        || err.contains("ApplicationClose")
        // QUIC idle timeout: Quinn surfaces this as the plain string "Timeout".
        // The session side already records a runtime failure; the driver task
        // logging it again at ERROR is redundant noise.
        || err.contains("Timeout")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "tests/shared.rs"]
mod tests;
