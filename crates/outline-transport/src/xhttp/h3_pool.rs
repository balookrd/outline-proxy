//! Carrier pool for XHTTP-over-H3 sessions.
//!
//! Until this module existed, every XHTTP session dialed its own QUIC
//! connection, and a QUIC connection is not cheap the way a stream is: quinn
//! gives each `Endpoint` a private UDP socket plus a receive buffer of
//! `max_udp_payload_size * gro_segments * BATCH_SIZE` — 2.87 MiB on Linux with
//! GRO. Measured on the fleet on 2026-08-22, 34 sessions meant 34 sockets and
//! 98 MiB of receive buffers against 102 MiB of RSS: the process was, to a
//! first approximation, made of those buffers.
//!
//! h3 exists to multiplex, so sessions now share connections: each session is
//! a request on a pooled connection, and the connections are spread across
//! slots the same way [`crate::h3`] spreads its WebSocket carriers. Slots are
//! what keeps a connection-level collapse (`H3_INTERNAL_ERROR`, a qpack fault,
//! an idle timeout) from taking every session on the uplink down together.
//!
//! What is deliberately *not* pooled is the dial itself: a fresh connection
//! still binds a fresh UDP socket, so the property per-dial ports were
//! introduced for — a NAT translation stuck on a dead path cannot pin future
//! dials — survives. Reuse applies to connections that already work.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use h3::client::SendRequest;
use rustls::pki_types::ServerName;
use tokio::time::timeout;
use tracing::debug;

use outline_metrics as metrics;

use crate::AbortOnDrop;
use crate::h3::{
    H3ConnectionGuard, TrackedEndpoint, choose_slot, classify_h3_close, client_endpoint,
    is_expected_h3_close,
};
use crate::shared_cache::{
    CachedEntry, CarrierIdleState, ConnLife, ConnLifeGuard, ConnLifeLevel, ConnectionKey,
    SharedConnectionRegistry, carriers_to_reap,
};

/// Same bound the rest of the H3 paths use for a fresh handshake.
const FRESH_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// Pool policy. The shape is [`choose_slot`]'s, the numbers are XHTTP's, because
// the unit of load here is a session rather than a WebSocket stream.
//
//  * MIN — carriers kept open once there is traffic. Lower than the WS pool's
//    floor of 4: there is no long-lived SSE stream to isolate here, only blast
//    radius to bound, and every extra carrier costs 2.87 MiB.
//  * CAP — soft ceiling on sessions per carrier; past it the picker opens
//    another one.
//  * MAX — hard ceiling on carriers per host, so a burst cannot reintroduce
//    the unbounded-connections behaviour this module exists to remove.
const XHTTP_H3_CARRIER_MIN: u8 = 2;
const XHTTP_H3_CARRIER_CAP: u64 = 32;
const XHTTP_H3_CARRIER_MAX: u8 = 8;

// Reaping. The sweep runs every 15 s, so eight sweeps is two minutes of
// carrying nothing before a carrier is closed.
//
// One warm carrier per server is kept, not `MIN`: the floor in `choose_slot`
// exists to spread *active* sessions, which is moot when there are none, while
// the floor here only has to save the next session a QUIC and an HTTP/3
// handshake. Traffic returning lifts the pool back to `MIN` on its own.
const REAP_AFTER_SWEEPS: u32 = 8;
const REAP_KEEP_WARM: u8 = 1;

// The floor has to fit under the ceiling and be worth having: a floor of 1
// would put every session of an uplink on one connection, which is the blast
// radius the slots exist to bound. Checked here rather than in a test so a
// future edit to the numbers cannot compile past it.
const _: () = assert!(XHTTP_H3_CARRIER_MIN >= 2);
const _: () = assert!(XHTTP_H3_CARRIER_MIN < XHTTP_H3_CARRIER_MAX);
const _: () = assert!(XHTTP_H3_CARRIER_CAP > 0);

/// Cache key: the logical server plus which carrier slot this dial targets.
///
/// Keyed on hostname rather than resolved address for the reason spelled out in
/// [`crate::h3`]: keying on the IP makes every DNS rotation orphan a live
/// connection in the map.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct XhttpH3Key {
    base: ConnectionKey,
    slot: u8,
}

impl XhttpH3Key {
    fn new(server_name: &str, server_port: u16, fwmark: Option<u32>, slot: u8) -> Self {
        Self {
            base: ConnectionKey::new(server_name, server_port, fwmark),
            slot,
        }
    }
}

/// One pooled QUIC connection carrying any number of XHTTP sessions.
pub(super) struct SharedXhttpH3Connection {
    id: u64,
    /// Never read, and load-bearing: the endpoint owns this connection's UDP
    /// socket and its receive buffer, both of which must outlive every session
    /// riding the connection. Dropping it is what frees the 2.87 MiB.
    #[allow(dead_code)]
    endpoint: TrackedEndpoint,
    connection: quinn::Connection,
    /// The pool's own handle. Never handed out — sessions get clones — but kept
    /// so the h3 driver never sees the last `SendRequest` go away, which it
    /// would read as "no more requests" and answer with a graceful shutdown.
    send_request: SendRequest<h3_quinn::OpenStreams, Bytes>,
    /// Sessions currently riding this carrier. Rises and falls with real usage
    /// through [`PooledSession`], and is what [`choose_slot`] balances on.
    active_sessions: Arc<AtomicU64>,
    /// Consecutive maintenance sweeps that found this carrier empty. Reset the
    /// moment a session lands on it.
    idle_sweeps: AtomicU32,
    /// Soft close: stops new sessions landing here without disturbing the ones
    /// already running. Closing the QUIC connection outright would kill them
    /// all — the mistake [`crate::h3`] documents.
    closed: AtomicBool,
    _connection_guard: H3ConnectionGuard,
    _driver_task: AbortOnDrop,
    // Declared last so it drops after the driver task: the driver is aborted
    // first, then this guard writes the close line the aborted task no longer
    // can.
    _conn_life: ConnLifeGuard,
}

impl SharedXhttpH3Connection {
    fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Relaxed) && self.connection.close_reason().is_none()
    }

    fn active(&self) -> u64 {
        self.active_sessions.load(Ordering::Relaxed)
    }
}

impl CachedEntry for SharedXhttpH3Connection {
    fn conn_id(&self) -> u64 {
        self.id
    }

    fn is_open(&self) -> bool {
        self.is_open()
    }
}

/// One session's hold on a pooled carrier.
///
/// Doubles as the session's [`crate::CarrierLossCounters`], which is what lets
/// the pool slot into the existing call path unchanged: `XhttpStream` already
/// keeps that `Arc` for exactly its own lifetime, so counting sessions and
/// keeping the carrier alive come out of the same object.
struct PooledSession {
    carrier: Arc<SharedXhttpH3Connection>,
}

impl PooledSession {
    fn new(carrier: Arc<SharedXhttpH3Connection>) -> Self {
        carrier.active_sessions.fetch_add(1, Ordering::Relaxed);
        Self { carrier }
    }
}

impl Drop for PooledSession {
    fn drop(&mut self) {
        self.carrier.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

impl crate::CarrierLossCounters for PooledSession {
    fn loss_counters(&self) -> Option<crate::CarrierLossSample> {
        let path = self.carrier.connection.stats().path;
        Some(crate::CarrierLossSample {
            sent: path.sent_packets,
            lost: path.lost_packets,
            alive: self.carrier.connection.close_reason().is_none(),
        })
    }
}

static REGISTRY: OnceLock<SharedConnectionRegistry<XhttpH3Key, SharedXhttpH3Connection>> =
    OnceLock::new();

fn registry() -> &'static SharedConnectionRegistry<XhttpH3Key, SharedXhttpH3Connection> {
    REGISTRY.get_or_init(SharedConnectionRegistry::new)
}

/// Read-only pass over the slots for one logical server, picking where a new
/// session should land. Uses `peek`, so probing never evicts.
async fn pick_slot(server_name: &str, server_port: u16, fwmark: Option<u32>) -> u8 {
    let mut loads: Vec<Option<u64>> = Vec::with_capacity(XHTTP_H3_CARRIER_MAX as usize);
    for slot in 0..XHTTP_H3_CARRIER_MAX {
        let key = XhttpH3Key::new(server_name, server_port, fwmark, slot);
        let load = match registry().peek(&key).await {
            Some(conn) if conn.is_open() => Some(conn.active()),
            _ => None,
        };
        loads.push(load);
    }
    choose_slot(&loads, XHTTP_H3_CARRIER_MIN, XHTTP_H3_CARRIER_CAP)
}

/// What one session needs from the carrier it rides.
pub(super) struct PooledCarrier {
    pub(super) send_request: SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub(super) loss_probe: Option<crate::CarrierLossProbe>,
    pub(super) carrier: Option<Arc<dyn crate::CarrierLossCounters>>,
}

/// Hand a session onto `carrier`: a private `SendRequest` clone, a loss probe
/// that observes without pinning, and the hold that keeps the carrier alive for
/// as long as the session runs.
fn session_on(carrier: Arc<SharedXhttpH3Connection>) -> PooledCarrier {
    let send_request = carrier.send_request.clone();
    let identity = carrier.connection.stable_id() as u64;
    let session: Arc<dyn crate::CarrierLossCounters> = Arc::new(PooledSession::new(carrier));
    // `Weak`, so the probe reports itself dead once the session lets go rather
    // than holding the carrier open for its own sake.
    let counters: Weak<dyn crate::CarrierLossCounters> = Arc::downgrade(&session);
    PooledCarrier {
        send_request,
        loss_probe: Some(crate::CarrierLossProbe::Quic { counters, identity }),
        carrier: Some(session),
    }
}

/// Reuse a pooled carrier for this session, dialing a new one when no open
/// carrier holds the chosen slot.
pub(super) async fn acquire(
    server_addr: SocketAddr,
    host: &str,
    port: u16,
    fwmark: Option<u32>,
) -> Result<PooledCarrier> {
    let slot = pick_slot(host, port, fwmark).await;
    let key = XhttpH3Key::new(host, port, fwmark, slot);

    if let Some(carrier) = registry().cached(&key).await {
        return Ok(session_on(carrier));
    }

    // Serialise dials per key so a burst of sessions opens one connection
    // between them instead of one each — which is the whole point.
    let lock = registry().connect_lock(&key);
    let _guard = lock.lock().await;
    if let Some(carrier) = registry().cached(&key).await {
        return Ok(session_on(carrier));
    }

    let carrier = Arc::new(dial(server_addr, host, fwmark, key.clone()).await?);
    registry().insert(key, Arc::clone(&carrier)).await;
    Ok(session_on(carrier))
}

async fn dial(
    server_addr: SocketAddr,
    host: &str,
    fwmark: Option<u32>,
    cache_key: XhttpH3Key,
) -> Result<SharedXhttpH3Connection> {
    let endpoint =
        client_endpoint(crate::bind_addr_for(server_addr), fwmark, metrics::H3_ENDPOINT_KIND_XHTTP)
            .with_context(|| format!("failed to bind xhttp/h3 QUIC endpoint for {server_addr}"))?;

    let server_name = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ServerName::IpAddress(ip.into())
    } else {
        ServerName::try_from(host.to_string())
            .map_err(|_| anyhow!("invalid TLS server name for xhttp/h3: {host}"))?
    };
    let server_name_str = match &server_name {
        ServerName::DnsName(name) => name.as_ref().to_owned(),
        _ => host.to_string(),
    };

    let connecting = endpoint
        .connect_with(crate::quic::h3_quic_client_config(), server_addr, &server_name_str)
        .with_context(|| format!("failed to initiate xhttp/h3 QUIC connection to {server_addr}"))?;
    let (connection, mut driver, send_request) = timeout(FRESH_CONNECT_TIMEOUT, async {
        let connection = connecting
            .await
            .with_context(|| format!("xhttp/h3 QUIC handshake failed for {server_addr}"))?;
        let (driver, send_request) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .context("xhttp/h3 HTTP/3 handshake failed")?;
        Ok::<_, anyhow::Error>((connection, driver, send_request))
    })
    .await
    .map_err(|_| {
        anyhow!(
            "xhttp/h3 fresh connect timed out after {}s to {server_addr}",
            FRESH_CONNECT_TIMEOUT.as_secs()
        )
    })??;

    let id = registry().next_id();
    // Sessions, not streams: the counter feeds the same `conn_life` diagnostics
    // the WS carriers use, where it answers "how much did this connection carry
    // before it died".
    let sessions_opened = Arc::new(AtomicU64::new(0));
    let conn_life = ConnLife::open(
        id,
        server_addr.to_string(),
        "xhttp_h3",
        ConnLifeLevel::Shared,
        Arc::clone(&sessions_opened),
    );
    let conn_life_driver = Arc::clone(&conn_life);
    let driver_task = AbortOnDrop::new(tokio::spawn(async move {
        let err = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        // Drop the entry as soon as the connection dies, so the next session
        // dials instead of waiting for the 15 s sweep to notice.
        registry().invalidate_if_current(&cache_key, id).await;
        let err_text = err.to_string();
        debug!(close = %err_text, "xhttp/h3 pooled carrier closed");
        conn_life_driver.close(
            Some(&err_text),
            classify_h3_close(&err_text),
            is_expected_h3_close(&err_text),
        );
    }));

    Ok(SharedXhttpH3Connection {
        id,
        endpoint,
        connection: connection.clone(),
        send_request,
        active_sessions: Arc::new(AtomicU64::new(0)),
        idle_sweeps: AtomicU32::new(0),
        closed: AtomicBool::new(false),
        _connection_guard: H3ConnectionGuard(connection),
        _driver_task: driver_task,
        _conn_life: ConnLifeGuard::new(conn_life),
    })
}

/// Drop carriers whose connection is gone, close the ones carrying nothing,
/// and publish the census. Called from the maintenance sweep that tends both
/// pools.
pub(crate) async fn gc() {
    registry().gc().await;

    // Group by logical server: the floor of warm carriers is per server, not
    // per process — a node with twenty uplinks would otherwise keep one carrier
    // in total and dial on every uplink switch.
    let mut by_server: HashMap<ConnectionKey, Vec<(XhttpH3Key, Arc<SharedXhttpH3Connection>)>> =
        HashMap::new();
    let (mut idle, mut busy) = (0usize, 0usize);
    for (key, carrier) in registry().entries().await {
        if carrier.active() == 0 {
            carrier.idle_sweeps.fetch_add(1, Ordering::Relaxed);
            idle += 1;
        } else {
            carrier.idle_sweeps.store(0, Ordering::Relaxed);
            busy += 1;
        }
        by_server.entry(key.base.clone()).or_default().push((key, carrier));
    }
    metrics::set_h3_pool_carriers(metrics::H3_ENDPOINT_KIND_XHTTP, idle, busy);

    for (_, carriers) in by_server {
        let census: Vec<CarrierIdleState> = carriers
            .iter()
            .map(|(key, carrier)| CarrierIdleState {
                slot: key.slot,
                active: carrier.active(),
                idle_sweeps: carrier.idle_sweeps.load(Ordering::Relaxed),
            })
            .collect();
        for slot in carriers_to_reap(&census, REAP_KEEP_WARM, REAP_AFTER_SWEEPS) {
            let Some((key, _)) = carriers.iter().find(|(key, _)| key.slot == slot) else {
                continue;
            };
            // Re-checked under the write lock: a session may have landed on
            // this carrier since the census was taken.
            if registry().remove_if(key, |carrier| carrier.active() == 0).await {
                metrics::record_h3_carrier_reaped(metrics::H3_ENDPOINT_KIND_XHTTP);
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/h3_pool.rs"]
mod tests;
