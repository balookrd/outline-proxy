//! Generic core shared by the per-target VLESS-UDP session muxes.
//!
//! VLESS UDP locks the target into the request header at session open,
//! so each destination needs its own session. Both muxes — WS
//! ([`super::udp_mux::VlessUdpSessionMux`]) and raw QUIC
//! ([`crate::VlessUdpQuicMux`]) — therefore share the same shape: a
//! lazy `target → session` map with LRU + idle eviction, a janitor
//! loop, and a downlink fan-in channel that re-frames every inbound
//! datagram with the originating session's SOCKS5 prefix. This module
//! owns that machinery once, generic over the session transport
//! ([`VlessUdpMuxSession`]) and the dial path ([`VlessUdpMuxDial`]);
//! the carrier-specific muxes contribute only their dialer (and any
//! side-channel bookkeeping such as resume IDs or downgrade latching)
//! plus the public constructors.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use parking_lot::RwLock as SyncRwLock;
use socks5_proto::TargetAddr;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, mpsc, watch};
use tracing::debug;

use crate::{AbortOnDrop, UplinkConnectionBinding, UpstreamTransportGuard, WsClosed};

/// Tuning parameters for the per-target session map. Defaults are picked
/// for a SOCKS/TUN client handling typical desktop workloads — DNS fan-out,
/// browser UDP, occasional QUIC/P2P.
#[derive(Clone, Copy, Debug)]
pub struct VlessUdpMuxLimits {
    /// Hard cap on concurrent VLESS UDP sessions. When the map is full, the
    /// least-recently-used session is evicted on insert so new destinations
    /// always make progress. A cap also bounds FD / memory pressure when a
    /// misbehaving client scans thousands of destinations.
    pub max_sessions: usize,
    /// Evict sessions whose `last_use` is older than this. `None` disables
    /// the janitor loop entirely (useful for tests).
    pub session_idle_timeout: Option<Duration>,
    /// How often the janitor scans for idle sessions. Ignored when
    /// `session_idle_timeout` is `None`.
    pub janitor_interval: Duration,
}

impl Default for VlessUdpMuxLimits {
    fn default() -> Self {
        Self {
            max_sessions: 256,
            session_idle_timeout: Some(Duration::from_secs(60)),
            janitor_interval: Duration::from_secs(15),
        }
    }
}

/// One per-target VLESS-UDP session as the mux core sees it: raw
/// datagram I/O plus close. Implemented by the WS transport and the
/// QUIC session; the signatures are identical on both, so the trait is
/// pure delegation.
pub(crate) trait VlessUdpMuxSession: Send + Sync + 'static {
    fn send_packet(&self, payload: &[u8]) -> impl Future<Output = Result<()>> + Send;
    fn read_packet(&self) -> impl Future<Output = Result<Bytes>> + Send;
    fn close(&self) -> impl Future<Output = Result<()>> + Send;
}

/// Dials one per-target session for the mux core. Carrier-specific
/// side effects — resume-ID bookkeeping, downgrade latching — live in
/// the implementation, behind this single call.
pub(crate) trait VlessUdpMuxDial: Send + Sync + 'static {
    type Session: VlessUdpMuxSession;
    fn dial(&self, target: &TargetAddr) -> impl Future<Output = Result<Arc<Self::Session>>> + Send;
}

pub(crate) struct VlessUdpMuxSessionEntry<S> {
    transport: Arc<S>,
    /// Wall-clock origin for `last_use_ns`. Captured once at session
    /// creation; the entry's lifespan is bounded by
    /// [`VlessUdpMuxLimits::session_idle_timeout`] (60 s default), so the
    /// `u64` ns counter has decades of headroom regardless of process
    /// uptime.
    created: Instant,
    /// Nanoseconds since `created` of the last send/read on this
    /// session. Updated lock-free on every `send_packet` / inbound
    /// datagram (the hot path); read by the LRU eviction scan and the
    /// idle-session janitor. Replaces a per-entry mutex that was
    /// acquired twice (set + read) on every UDP datagram.
    last_use_ns: AtomicU64,
    _reader_task: AbortOnDrop,
}

impl<S> VlessUdpMuxSessionEntry<S> {
    fn new(transport: Arc<S>, reader_task: AbortOnDrop) -> Self {
        Self {
            transport,
            created: Instant::now(),
            last_use_ns: AtomicU64::new(0),
            _reader_task: reader_task,
        }
    }

    fn touch(&self) {
        // Saturate at u64::MAX rather than wrapping — we'd lose ordering
        // for the LRU comparator otherwise. With a 60 s idle timeout the
        // counter never gets near saturation in practice.
        let ns = u64::try_from(self.created.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_use_ns.store(ns, Ordering::Relaxed);
    }

    fn last_use(&self) -> Instant {
        let ns = self.last_use_ns.load(Ordering::Relaxed);
        self.created + Duration::from_nanos(ns)
    }
}

/// Wrapper that lets `OnceCell::get_or_try_init` serialize concurrent
/// dial attempts for the same `TargetAddr`. The cell is empty while
/// the first dial is in flight; subsequent callers `await` the same
/// future and re-emerge with the populated [`VlessUdpMuxSessionEntry`].
///
/// `created` is captured at slot insertion so the LRU comparator and
/// idle-session janitor have a meaningful "age" for in-flight slots
/// whose `cell` has not been populated yet.
pub(super) struct VlessUdpMuxSessionSlot<S> {
    cell: OnceCell<Arc<VlessUdpMuxSessionEntry<S>>>,
    pub(super) created: Instant,
}

impl<S> VlessUdpMuxSessionSlot<S> {
    pub(super) fn new() -> Self {
        Self {
            cell: OnceCell::new(),
            created: Instant::now(),
        }
    }

    pub(super) fn entry(&self) -> Option<&Arc<VlessUdpMuxSessionEntry<S>>> {
        self.cell.get()
    }

    /// Effective LRU stamp. Falls back to slot creation time for
    /// in-flight (cell-empty) slots so the eviction scan still has a
    /// totally-ordered key over the whole map; populated slots use
    /// the entry's lock-free atomic stamp.
    pub(super) fn last_use(&self) -> Instant {
        self.cell.get().map(|e| e.last_use()).unwrap_or(self.created)
    }
}

type SessionMap<S> = Arc<SyncRwLock<HashMap<TargetAddr, Arc<VlessUdpMuxSessionSlot<S>>>>>;

/// The shared mux machinery: session map, downlink fan-in, janitor and
/// close plumbing. Carrier muxes embed one of these and forward their
/// public API into it.
pub(crate) struct VlessUdpMuxCore<D: VlessUdpMuxDial> {
    /// The carrier-specific dialer. Exposed so the WS mux can reach
    /// its builder-style knobs (downgrade hook, test latch accessors)
    /// after construction.
    pub(crate) dial: D,
    limits: VlessUdpMuxLimits,
    /// Short label distinguishing the carriers in error contexts and
    /// log lines ("vless udp" / "vless udp quic").
    kind: &'static str,
    sessions: SessionMap<D::Session>,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    downlink_rx: AsyncMutex<mpsc::Receiver<Result<Bytes>>>,
    close_signal: watch::Sender<bool>,
    _janitor_task: Option<AbortOnDrop>,
    lifetime: Arc<UpstreamTransportGuard>,
}

impl<D: VlessUdpMuxDial> VlessUdpMuxCore<D> {
    pub(crate) fn new(
        dial: D,
        limits: VlessUdpMuxLimits,
        kind: &'static str,
        source: &'static str,
    ) -> Self {
        let (close_signal, _close_rx) = watch::channel(false);
        let (downlink_tx, downlink_rx) = mpsc::channel::<Result<Bytes>>(256);
        let sessions: SessionMap<D::Session> = Arc::new(SyncRwLock::new(HashMap::new()));
        let janitor_task = limits.session_idle_timeout.map(|idle_timeout| {
            spawn_vless_udp_mux_janitor(
                Arc::clone(&sessions),
                idle_timeout,
                limits.janitor_interval,
                close_signal.subscribe(),
                kind,
            )
        });
        Self {
            dial,
            limits,
            kind,
            sessions,
            downlink_tx,
            downlink_rx: AsyncMutex::new(downlink_rx),
            close_signal,
            _janitor_task: janitor_task,
            lifetime: UpstreamTransportGuard::new(source, "udp"),
        }
    }

    /// See [`crate::UdpWsTransport::with_uplink_binding`] for the
    /// constraints; both muxes expose this via their own builder method.
    pub(crate) fn attach_uplink_binding(&mut self, binding: UplinkConnectionBinding) {
        UpstreamTransportGuard::attach_uplink_binding(&mut self.lifetime, binding);
    }

    /// Send a SOCKS5-framed UDP payload (`atyp || addr || port || data`).
    /// The target is parsed out to select an existing VLESS session or open
    /// a new one; only the `data` portion crosses the VLESS wire, since the
    /// target is already bound into the session's request header.
    pub(crate) async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        let (target, consumed) =
            TargetAddr::from_wire_bytes(socks5_payload).with_context(|| {
                format!("{}: failed to parse SOCKS5 header from outbound payload", self.kind)
            })?;
        let inner = &socks5_payload[consumed..];
        let session = self.session_for(&target).await?;
        session.touch();
        session.transport.send_packet(inner).await
    }

    /// Read the next downlink datagram as a SOCKS5-framed payload, with the
    /// originating session's `TargetAddr` prepended so the caller can parse
    /// it exactly like the SS UDP path.
    pub(crate) async fn read_packet(&self) -> Result<Bytes> {
        let mut rx = self.downlink_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::Error::from(WsClosed))?
    }

    pub(crate) async fn close(&self) -> Result<()> {
        self.close_signal.send_replace(true);
        let sessions = {
            let mut guard = self.sessions.write();
            std::mem::take(&mut *guard)
        };
        for (_, slot) in sessions {
            // In-flight slots have no transport yet; their first
            // `read_packet` after dial sees `close_signal=true` via the
            // session-reader task and exits, and the dial future itself
            // is dropped together with the last slot reference we just
            // released by clearing the map.
            if let Some(entry) = slot.entry() {
                let _ = entry.transport.close().await;
            }
        }
        Ok(())
    }

    pub(crate) async fn session_for(
        &self,
        target: &TargetAddr,
    ) -> Result<Arc<VlessUdpMuxSessionEntry<D::Session>>> {
        // Fast path: populated slot for this target. Concurrent senders
        // to *different* targets share a read guard so they don't
        // serialize, and `entry.touch()` updates the LRU timestamp
        // lock-free via a relaxed atomic store.
        {
            let guard = self.sessions.read();
            if let Some(slot) = guard.get(target)
                && let Some(entry) = slot.entry()
            {
                entry.touch();
                return Ok(Arc::clone(entry));
            }
        }
        // Slow path: get-or-create the slot, then `OnceCell::get_or_try_init`
        // serializes the dial. Only the first concurrent caller actually
        // runs the handshake; the rest await the same future and emerge
        // with the same entry. If the future errors, the cell stays empty
        // and the next call retries.
        let (slot, evicted) = {
            let mut guard = self.sessions.write();
            // Re-check (TOCTOU) before allocating a fresh slot.
            if let Some(existing) = guard.get(target) {
                (Arc::clone(existing), None)
            } else {
                let evicted = if guard.len() >= self.limits.max_sessions {
                    // LRU eviction. Skip in-flight slots — abandoning their
                    // shared dial future would force every blocked waiter
                    // to restart with a fresh handshake.
                    evict_lru_populated_session(&mut guard)
                } else {
                    None
                };
                let slot = Arc::new(VlessUdpMuxSessionSlot::new());
                guard.insert(target.clone(), Arc::clone(&slot));
                (slot, evicted)
            }
        };
        if let Some(victim) = evicted {
            debug!(
                target: "outline_transport::vless",
                kind = self.kind,
                "vless udp mux at max_sessions, evicted LRU session to make room"
            );
            let _ = victim.transport.close().await;
        }
        let dial_outcome = slot
            .cell
            .get_or_try_init(|| async {
                let transport = self.dial.dial(target).await?;
                let reader_task = spawn_vless_udp_mux_session_reader(
                    Arc::clone(&transport),
                    target.clone(),
                    self.downlink_tx.clone(),
                    self.close_signal.subscribe(),
                    self.kind,
                );
                Ok::<_, anyhow::Error>(Arc::new(VlessUdpMuxSessionEntry::new(
                    transport,
                    reader_task,
                )))
            })
            .await;
        match dial_outcome {
            Ok(entry) => {
                entry.touch();
                Ok(Arc::clone(entry))
            },
            Err(error) => {
                // Best-effort cleanup: drop the failed slot from the map
                // so a fresh `session_for` allocates a new one rather
                // than retrying through this still-empty cell. If a
                // concurrent caller already replaced the slot we leave
                // theirs alone (Arc::ptr_eq guard).
                let mut guard = self.sessions.write();
                if let Some(existing) = guard.get(target)
                    && Arc::ptr_eq(existing, &slot)
                {
                    guard.remove(target);
                }
                Err(error)
            },
        }
    }
}

/// Pick the LRU populated slot. In-flight (cell-empty) slots are
/// skipped because evicting them would cancel the shared dial future
/// and force every blocked `session_for` waiter to retry from scratch.
/// In the pathological case where every slot is in-flight at once, no
/// eviction happens and the map briefly exceeds `max_sessions`; this
/// resolves on its own as soon as one of the dials completes.
pub(super) fn evict_lru_populated_session<S>(
    guard: &mut HashMap<TargetAddr, Arc<VlessUdpMuxSessionSlot<S>>>,
) -> Option<Arc<VlessUdpMuxSessionEntry<S>>> {
    let oldest_key = guard
        .iter()
        .filter(|(_, slot)| slot.entry().is_some())
        .min_by_key(|(_, slot)| slot.last_use())
        .map(|(k, _)| k.clone())?;
    let slot = guard.remove(&oldest_key)?;
    // `entry()` is `Some` here by construction (filter above).
    slot.entry().map(Arc::clone)
}

fn spawn_vless_udp_mux_janitor<S: VlessUdpMuxSession>(
    sessions: SessionMap<S>,
    idle_timeout: Duration,
    interval: Duration,
    mut close_rx: watch::Receiver<bool>,
    kind: &'static str,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // consume the immediate tick
        loop {
            tokio::select! {
                biased;
                _ = close_rx.changed() => {
                    if *close_rx.borrow() { return; }
                }
                _ = ticker.tick() => {}
            }
            let now = Instant::now();
            let expired: Vec<Arc<VlessUdpMuxSessionEntry<S>>> = {
                // Two-phase scan: walk under a cheap read lock to find
                // candidates, then acquire the write lock briefly to
                // remove them. A single write-locked pass would block
                // every send_packet for the full O(N) scan.
                let candidates: Vec<TargetAddr> = {
                    let read_guard = sessions.read();
                    read_guard
                        .iter()
                        .filter(|(_, slot)| {
                            // Use `slot.last_use()` so the predicate is
                            // uniform: populated slots use the entry's
                            // atomic stamp, empty (in-flight) slots use
                            // `created`. An in-flight slot whose dial has
                            // been hanging for `idle_timeout` is almost
                            // certainly stuck — evicting it cancels the
                            // dial future and lets the next caller try
                            // afresh, preferable to indefinite blockage.
                            now.saturating_duration_since(slot.last_use()) >= idle_timeout
                        })
                        .map(|(k, _)| k.clone())
                        .collect()
                };
                if candidates.is_empty() {
                    Vec::new()
                } else {
                    let mut guard = sessions.write();
                    candidates
                        .into_iter()
                        .filter_map(|k| {
                            // Re-check the staleness predicate under the
                            // write lock — a sender may have touched the
                            // entry between the read-side scan and now.
                            // Skip if it has, so an active session never
                            // gets accidentally evicted by the janitor.
                            guard.get(&k).filter(|slot| {
                                now.saturating_duration_since(slot.last_use()) >= idle_timeout
                            })?;
                            // `entry()` returns `None` for in-flight slots —
                            // we still want them evicted (the dial future
                            // dies with the last Arc), but there's no
                            // transport to close.
                            guard.remove(&k).and_then(|s| s.entry().map(Arc::clone))
                        })
                        .collect()
                }
            };
            if !expired.is_empty() {
                debug!(
                    target: "outline_transport::vless",
                    kind,
                    count = expired.len(),
                    idle_secs = idle_timeout.as_secs(),
                    "vless udp mux: evicting idle sessions"
                );
            }
            for entry in expired {
                let _ = entry.transport.close().await;
            }
        }
    }))
}

fn spawn_vless_udp_mux_session_reader<S: VlessUdpMuxSession>(
    transport: Arc<S>,
    target: TargetAddr,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    mut close_rx: watch::Receiver<bool>,
    kind: &'static str,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        // Pre-build the SOCKS5 wire prefix for this session's target —
        // every downlink datagram carries the same one.
        let prefix = match target.to_wire_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = downlink_tx
                    .send(Err(anyhow::Error::from(error).context(format!(
                        "{kind}: failed to encode session target to SOCKS5 wire form"
                    ))))
                    .await;
                return;
            },
        };
        loop {
            let payload = tokio::select! {
                biased;
                _ = close_rx.changed() => {
                    if *close_rx.borrow() { return; }
                    continue;
                }
                res = transport.read_packet() => match res {
                    Ok(p) => p,
                    Err(error) => {
                        // Per-session failure: surface it so the caller can
                        // treat it as a transport-level error, then exit —
                        // a replacement session will be opened on the next
                        // send to this target.
                        let _ = downlink_tx.send(Err(error)).await;
                        return;
                    }
                },
            };
            let mut framed = BytesMut::with_capacity(prefix.len() + payload.len());
            framed.extend_from_slice(&prefix);
            framed.extend_from_slice(&payload);
            if downlink_tx.send(Ok(framed.freeze())).await.is_err() {
                return;
            }
        }
    }))
}
