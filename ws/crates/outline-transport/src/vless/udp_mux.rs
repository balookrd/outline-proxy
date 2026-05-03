//! Lazy per-target VLESS-UDP session multiplexer that exposes a
//! Shadowsocks-shaped (SOCKS5-framed) datagram API.
//!
//! Shadowsocks UDP multiplexes all destinations through one encrypted session
//! (the target address is carried as a SOCKS-style atyp prefix in every
//! datagram). VLESS UDP has no such prefix: the target is locked into the
//! request header at session open, so each destination needs its own
//! WebSocket session. `VlessUdpSessionMux` provides an SS-shaped API
//! (`send_packet(socks5_framed_payload)` / `read_packet() -> socks5_framed`)
//! on top of a lazy map of per-target VLESS sessions.
//!
//! The on-wire framing delta is absorbed by stripping the SOCKS5 UDP header
//! on send (to select/open the session and forward the raw payload) and
//! prepending it on receive (so the caller's existing `TargetAddr::from_wire_bytes`
//! parse still works).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use parking_lot::RwLock as SyncRwLock;
use socks5_proto::TargetAddr;
use tokio::sync::{Mutex as AsyncMutex, OnceCell, mpsc, watch};
use tracing::debug;
use url::Url;

use crate::{
    AbortOnDrop, DnsCache, TransportOperation, UpstreamTransportGuard, WsClosed,
    config::TransportMode, resumption::SessionId,
};

use super::udp::VlessUdpWsTransport;

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

/// Synchronous callback fired by the mux the first time a per-target dial
/// silently downgrades from H3 to H2/H1 (host-level `ws_mode_cache` clamp
/// or inline H3-handshake fallback inside `connect_websocket_with_resume`).
/// Receives the originally-requested mode so the uplink-manager caller can
/// record it via `note_silent_transport_fallback`. Distinct from the
/// QUIC-only `vless_udp_hybrid::FallbackNotifier` which carries an error
/// (the QUIC dial actually failed); here the dial succeeded but at a lower
/// mode, so passing the requested mode directly is cleaner than synthesising
/// an error to extract the mode from.
pub type VlessUdpDowngradeNotifier = Arc<dyn Fn(TransportMode) + Send + Sync>;

pub struct VlessUdpSessionMux {
    dial: VlessUdpSessionDialer,
    limits: VlessUdpMuxLimits,
    /// Hot map of `target → slot`. Each slot wraps a
    /// [`tokio::sync::OnceCell`] that is lazy-filled by the first
    /// `session_for` call to dial that target — concurrent callers
    /// for the same target await the same future via
    /// `OnceCell::get_or_try_init`, so a burst of UDP datagrams to a
    /// fresh CDN edge triggers exactly one WS Upgrade instead of N
    /// parallel handshakes that race and discard losers (the
    /// "thundering herd" pattern). An [`SyncRwLock`] lets concurrent
    /// senders to *different* targets run their fast-path lookups in
    /// parallel.
    sessions: Arc<SyncRwLock<HashMap<TargetAddr, Arc<VlessUdpSessionSlot>>>>,
    /// Session IDs the server assigned to each per-target VLESS-UDP-WS
    /// session, keyed by target. On the *next* dial for the same
    /// target the cached ID is presented as `X-Outline-Resume`, so a
    /// feature-enabled outline-ss-rust server can re-attach the
    /// parked `Arc<UdpSocket>` instead of binding a fresh source
    /// port. The map is intentionally separate from the global
    /// `outline_transport::ResumeCache` because a single uplink mux
    /// fans out to many targets and each carries its own Session ID.
    resume_ids: Arc<SyncRwLock<HashMap<TargetAddr, SessionId>>>,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    downlink_rx: AsyncMutex<mpsc::Receiver<Result<Bytes>>>,
    close_signal: watch::Sender<bool>,
    _janitor_task: Option<AbortOnDrop>,
    _lifetime: Arc<UpstreamTransportGuard>,
    /// Optional hook fired the first time a per-target dial returns a
    /// stream that was silently downgraded from H3 to H2/H1 by the
    /// transport layer. Latched: subsequent downgraded dials are
    /// suppressed by `downgrade_reported` so we don't spam the
    /// uplink-manager once per target. Set via [`Self::with_on_downgrade`].
    on_downgrade: Option<VlessUdpDowngradeNotifier>,
    /// Latch for `on_downgrade`: ensures the notifier fires at most once
    /// per mux instance regardless of how many per-target sessions are
    /// dialed during the H3 outage.
    downgrade_reported: AtomicBool,
}

/// Captured connection parameters used to dial a new per-target VLESS UDP
/// session on demand. Everything here is cheap to clone and carries no
/// target-specific state.
#[derive(Clone)]
struct VlessUdpSessionDialer {
    dns_cache: Arc<DnsCache>,
    url: Url,
    mode: TransportMode,
    uuid: [u8; 16],
    fwmark: Option<u32>,
    ipv6_first: bool,
    source: &'static str,
    keepalive_interval: Option<Duration>,
}

pub(crate) struct VlessUdpSessionEntry {
    transport: Arc<VlessUdpWsTransport>,
    /// Wall-clock origin for `last_use_ns`. Captured once at session
    /// creation; the entry's lifespan is bounded by
    /// `VlessUdpMuxLimits::session_idle_timeout` (60 s default), so the
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

impl VlessUdpSessionEntry {
    fn new(transport: Arc<VlessUdpWsTransport>, reader_task: AbortOnDrop) -> Self {
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
/// future and re-emerge with the populated [`VlessUdpSessionEntry`].
///
/// `created` is captured at slot insertion so the LRU comparator and
/// idle-session janitor have a meaningful "age" for in-flight slots
/// whose `cell` has not been populated yet.
pub(super) struct VlessUdpSessionSlot {
    cell: OnceCell<Arc<VlessUdpSessionEntry>>,
    pub(super) created: Instant,
}

impl VlessUdpSessionSlot {
    pub(super) fn new() -> Self {
        Self { cell: OnceCell::new(), created: Instant::now() }
    }

    pub(super) fn entry(&self) -> Option<&Arc<VlessUdpSessionEntry>> {
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

impl VlessUdpSessionMux {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dns_cache: Arc<DnsCache>,
        url: Url,
        mode: TransportMode,
        uuid: [u8; 16],
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
    ) -> Self {
        Self::new_with_limits(
            dns_cache,
            url,
            mode,
            uuid,
            fwmark,
            ipv6_first,
            source,
            keepalive_interval,
            VlessUdpMuxLimits::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_limits(
        dns_cache: Arc<DnsCache>,
        url: Url,
        mode: TransportMode,
        uuid: [u8; 16],
        fwmark: Option<u32>,
        ipv6_first: bool,
        source: &'static str,
        keepalive_interval: Option<Duration>,
        limits: VlessUdpMuxLimits,
    ) -> Self {
        let (close_signal, _close_rx) = watch::channel(false);
        let (downlink_tx, downlink_rx) = mpsc::channel::<Result<Bytes>>(256);
        let sessions: Arc<SyncRwLock<HashMap<TargetAddr, Arc<VlessUdpSessionSlot>>>> =
            Arc::new(SyncRwLock::new(HashMap::new()));
        let janitor_task = limits.session_idle_timeout.map(|idle_timeout| {
            spawn_vless_udp_janitor(
                Arc::clone(&sessions),
                idle_timeout,
                limits.janitor_interval,
                close_signal.subscribe(),
            )
        });
        Self {
            dial: VlessUdpSessionDialer {
                dns_cache,
                url,
                mode,
                uuid,
                fwmark,
                ipv6_first,
                source,
                keepalive_interval,
            },
            limits,
            sessions,
            resume_ids: Arc::new(SyncRwLock::new(HashMap::new())),
            downlink_tx,
            downlink_rx: AsyncMutex::new(downlink_rx),
            close_signal,
            _janitor_task: janitor_task,
            _lifetime: UpstreamTransportGuard::new(source, "udp"),
            on_downgrade: None,
            downgrade_reported: AtomicBool::new(false),
        }
    }

    /// Attach a downgrade-detection hook fired the first time a per-target
    /// dial returns a stream that was silently downgraded from H3 to H2/H1
    /// by the transport layer (host-level `ws_mode_cache` clamp or inline
    /// fallback inside `connect_websocket_with_resume`). Latched: fires at
    /// most once per mux instance regardless of how many subsequent dials
    /// also see the downgrade. Without this, `effective_udp_mode` keeps
    /// reporting H3 in the uplink-manager while every actual session dial
    /// is silently clamped to H2 — the "vless/ws/h3 stays put" symptom.
    pub fn with_on_downgrade(mut self, hook: Option<VlessUdpDowngradeNotifier>) -> Self {
        self.on_downgrade = hook;
        self
    }

    /// Send a SOCKS5-framed UDP payload (`atyp || addr || port || data`).
    /// The target is parsed out to select an existing VLESS session or open
    /// a new one; only the `data` portion crosses the VLESS wire, since the
    /// target is already bound into the session's request header.
    pub async fn send_packet(&self, socks5_payload: &[u8]) -> Result<()> {
        let (target, consumed) = TargetAddr::from_wire_bytes(socks5_payload)
            .context("vless udp: failed to parse SOCKS5 header from outbound payload")?;
        let inner = &socks5_payload[consumed..];
        let session = self.session_for(&target).await?;
        session.touch();
        session.transport.send_packet(inner).await
    }

    /// Read the next downlink datagram as a SOCKS5-framed payload, with the
    /// originating session's `TargetAddr` prepended so the caller can parse
    /// it exactly like the SS UDP path.
    pub async fn read_packet(&self) -> Result<Bytes> {
        let mut rx = self.downlink_rx.lock().await;
        rx.recv().await.ok_or_else(|| anyhow::Error::from(WsClosed))?
    }

    pub async fn close(&self) -> Result<()> {
        self.close_signal.send_replace(true);
        let sessions = {
            let mut guard = self.sessions.write();
            std::mem::take(&mut *guard)
        };
        for (_, slot) in sessions {
            // In-flight slots have no transport yet; their first
            // `read_packet` after dial sees `close_signal=true` via the
            // session-reader task and exits, and the dial future itself
            // is dropped together with the last `Arc<VlessUdpSessionSlot>`
            // reference we just released by clearing the map.
            if let Some(entry) = slot.entry() {
                let _ = entry.transport.close().await;
            }
        }
        Ok(())
    }

    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn downgrade_latch_for_test(&self) -> bool {
        self.downgrade_reported.load(Ordering::Acquire)
    }

    /// Test-only entry point that simulates the latch-reset path the mux
    /// runs whenever a per-target dial succeeds at the requested mode after
    /// a previous downgrade. Used by `vless_udp_mux_resets_downgrade_latch_*`
    /// to drive the recovery branch without standing up a server that can
    /// alternate between H3-up and H3-down on demand.
    #[cfg(all(test, feature = "metrics"))]
    pub(crate) fn force_reset_downgrade_latch_for_test(&self) {
        self.downgrade_reported.store(false, Ordering::Release);
    }

    pub(crate) async fn session_for(
        &self,
        target: &TargetAddr,
    ) -> Result<Arc<VlessUdpSessionEntry>> {
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
        // runs the WS upgrade; the rest await the same future and emerge
        // with the same `Arc<VlessUdpSessionEntry>`. If the future errors,
        // the cell stays empty and the next call retries.
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
                let slot = Arc::new(VlessUdpSessionSlot::new());
                guard.insert(target.clone(), Arc::clone(&slot));
                (slot, evicted)
            }
        };
        if let Some(victim) = evicted {
            debug!(
                target: "outline_transport::vless",
                "vless udp mux at max_sessions, evicted LRU session to make room"
            );
            let _ = victim.transport.close().await;
        }
        // Cross-transport resumption: present the previously-issued
        // Session ID for this target so a feature-enabled server can
        // re-attach its parked `Arc<UdpSocket>` instead of binding a
        // fresh source port. Read under a short shared lock to keep
        // the slow path's contention narrow.
        let resume_request = self.resume_ids.read().get(target).copied();
        let resume_ids_for_dial = Arc::clone(&self.resume_ids);
        let target_for_dial = target.clone();
        let dial_outcome = slot
            .cell
            .get_or_try_init(|| async {
                let (raw_transport, issued, downgraded_from) =
                    VlessUdpWsTransport::connect_with_resume(
                        &self.dial.dns_cache,
                        &self.dial.url,
                        self.dial.mode,
                        &self.dial.uuid,
                        &target_for_dial,
                        self.dial.fwmark,
                        self.dial.ipv6_first,
                        self.dial.source,
                        self.dial.keepalive_interval,
                        resume_request,
                    )
                    .await
                    .with_context(|| TransportOperation::Connect {
                        target: format!("vless udp session to {target_for_dial}"),
                    })?;
                if let Some(id) = issued {
                    resume_ids_for_dial.write().insert(target_for_dial.clone(), id);
                }
                // Mirror a transport-level WS-mode downgrade (clamp or inline
                // H3→H2/H1 fallback) into the uplink-manager via the latched
                // hook. The compare_exchange ensures the notifier fires at
                // most once per mux instance even if multiple per-target
                // dials race during the same H3 outage window.
                //
                // Reset the latch on the first dial that succeeds at the
                // requested mode after a previous downgrade — this lets the
                // hook fire again if H3 recovers and then drops out a second
                // time during the lifetime of this mux instance.  Without
                // this the latch would be one-shot for the lifetime of the
                // process under long-lived muxes, hiding subsequent outages
                // from the per-uplink window.
                match downgraded_from {
                    Some(requested) => {
                        if let Some(hook) = self.on_downgrade.as_ref()
                            && self
                                .downgrade_reported
                                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                                .is_ok()
                        {
                            hook(requested);
                        }
                    }
                    None => {
                        // Cheap relaxed-style store; racing with a Some-branch
                        // CAS just means the next downgraded dial flips it
                        // back to true via the same CAS.
                        self.downgrade_reported.store(false, Ordering::Release);
                    }
                }
                let transport = Arc::new(raw_transport);
                let reader_task = spawn_vless_udp_session_reader(
                    Arc::clone(&transport),
                    target_for_dial.clone(),
                    self.downlink_tx.clone(),
                    self.close_signal.subscribe(),
                );
                Ok::<_, anyhow::Error>(Arc::new(VlessUdpSessionEntry::new(
                    transport,
                    reader_task,
                )))
            })
            .await;
        match dial_outcome {
            Ok(entry) => {
                entry.touch();
                Ok(Arc::clone(entry))
            }
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
            }
        }
    }
}

/// Pick the LRU populated slot. In-flight (cell-empty) slots are
/// skipped because evicting them would cancel the shared dial future
/// and force every blocked `session_for` waiter to retry from scratch.
/// In the pathological case where every slot is in-flight at once, no
/// eviction happens and the map briefly exceeds `max_sessions`; this
/// resolves on its own as soon as one of the dials completes.
pub(super) fn evict_lru_populated_session(
    guard: &mut HashMap<TargetAddr, Arc<VlessUdpSessionSlot>>,
) -> Option<Arc<VlessUdpSessionEntry>> {
    let oldest_key = guard
        .iter()
        .filter(|(_, slot)| slot.entry().is_some())
        .min_by_key(|(_, slot)| slot.last_use())
        .map(|(k, _)| k.clone())?;
    let slot = guard.remove(&oldest_key)?;
    // `entry()` is `Some` here by construction (filter above).
    slot.entry().map(Arc::clone)
}

fn spawn_vless_udp_janitor(
    sessions: Arc<SyncRwLock<HashMap<TargetAddr, Arc<VlessUdpSessionSlot>>>>,
    idle_timeout: Duration,
    interval: Duration,
    mut close_rx: watch::Receiver<bool>,
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
            let expired: Vec<Arc<VlessUdpSessionEntry>> = {
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
                                now.saturating_duration_since(slot.last_use())
                                    >= idle_timeout
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

fn spawn_vless_udp_session_reader(
    transport: Arc<VlessUdpWsTransport>,
    target: TargetAddr,
    downlink_tx: mpsc::Sender<Result<Bytes>>,
    mut close_rx: watch::Receiver<bool>,
) -> AbortOnDrop {
    AbortOnDrop::new(tokio::spawn(async move {
        // Pre-build the SOCKS5 wire prefix for this session's target —
        // every downlink datagram carries the same one.
        let prefix = match target.to_wire_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = downlink_tx
                    .send(Err(anyhow::Error::from(error).context(
                        "vless udp: failed to encode session target to SOCKS5 wire form",
                    )))
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

