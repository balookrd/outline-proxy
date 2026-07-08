//! In-memory registry of parked upstream sessions awaiting cross-transport resume.
//!
//! All entries live in process memory; nothing survives a restart. See
//! `docs/SESSION-RESUMPTION.md` for the lifecycle model.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use outline_wire::cluster::{ObfuscationKey, ShardId};
use parking_lot::Mutex;
use ring::rand::SystemRandom;
use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::metrics::Metrics;

use super::{config::ResumptionConfig, parked::Parked, session_id::SessionId};

/// Upper bound on how long a `take_for_resume` waits for an in-flight park to
/// commit before concluding a miss. The park side only holds a reservation
/// across the reader harvest (a cancel-notify plus one task join), which is
/// sub-millisecond in practice; this is a generous ceiling so a wedged or
/// panicking parker can never hang a resume indefinitely.
const RESERVATION_WAIT: Duration = Duration::from_secs(5);

/// This server's cluster identity: the shard it owns and the key that
/// obfuscates it inside minted session ids. `None` when the server is not part
/// of a cluster, in which case ids are plain random. Wired from `[cluster]`
/// config in a later phase; see `docs/CLUSTER.md`.
#[derive(Clone)]
pub(crate) struct ClusterIdentity {
    pub(crate) key: ObfuscationKey,
    pub(crate) shard: ShardId,
}

/// Reason a `take_for_resume` call did not return parked state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeMiss {
    /// No entry indexed by this Session ID exists, or it expired.
    Unknown,
    /// Entry exists but belongs to a different authenticated user. We
    /// surface this externally as `Unknown` to avoid an existence oracle;
    /// the distinct variant is kept so callers can log a security event.
    OwnerMismatch,
    /// Resumption is disabled by config.
    Disabled,
}

impl ResumeMiss {
    /// Stable label exposed via the `reason` metric dimension. Hides
    /// `OwnerMismatch` behind `unknown` to avoid leaking ID existence.
    pub(crate) fn metric_reason(self) -> &'static str {
        match self {
            Self::Unknown | Self::OwnerMismatch => "unknown",
            Self::Disabled => "disabled",
        }
    }
}

pub(crate) enum ResumeOutcome {
    Hit(Parked),
    /// Resume failed; production callers do not switch on the inner
    /// reason (the only behavioural difference is the metric label,
    /// which is recorded inside `take_for_resume`). Tests do match on
    /// it, hence `dead_code` allow rather than removing the payload.
    #[allow(dead_code)]
    Miss(ResumeMiss),
}

/// Internal envelope wrapping a payload with bookkeeping fields.
struct ParkedEntry {
    owner: Arc<str>,
    deadline: Instant,
    parked: Parked,
}

/// Process-wide registry of parked sessions.
pub(crate) struct OrphanRegistry {
    config: ResumptionConfig,
    rng: SystemRandom,
    by_id: DashMap<SessionId, ParkedEntry>,
    /// Session ids with a park *in flight*: reserved before the parking side
    /// harvests its reader (a step that awaits), and cleared once the entry is
    /// committed to `by_id` or the park is abandoned. A concurrent
    /// [`Self::take_for_resume`] that finds no committed entry but an active
    /// reservation waits on the entry's `Notify` instead of declaring a miss —
    /// this closes the park-miss race where a fast client redial arrived in the
    /// window between the old carrier closing and the park landing.
    reservations: DashMap<SessionId, Arc<Notify>>,
    /// Per-user index for cap enforcement and bulk eviction. The Mutex
    /// scope is narrow and contention is bounded by `orphan_per_user_cap`
    /// (4 by default), so a parking_lot mutex is preferred over a per-key
    /// async lock.
    per_user: DashMap<Arc<str>, Mutex<Vec<SessionId>>>,
    /// This server's cluster identity, or `None` when not clustered. When set,
    /// minted session ids carry this shard (obfuscated); otherwise they are
    /// plain random and byte-compatible with the pre-cluster behaviour.
    cluster: Option<ClusterIdentity>,
    metrics: Arc<Metrics>,
}

impl OrphanRegistry {
    pub(crate) fn new(config: ResumptionConfig, metrics: Arc<Metrics>) -> Self {
        Self {
            config,
            rng: SystemRandom::new(),
            by_id: DashMap::new(),
            reservations: DashMap::new(),
            per_user: DashMap::new(),
            cluster: None,
            metrics,
        }
    }

    /// Attaches this server's cluster identity so minted session ids carry the
    /// shard. Builder-style so existing constructor call sites are unchanged;
    /// wired from `[cluster]` config at startup (see `server::services`).
    pub(crate) fn with_cluster(mut self, key: ObfuscationKey, shard: ShardId) -> Self {
        self.cluster = Some(ClusterIdentity { key, shard });
        self
    }

    /// Convenience constructor for production paths and test fixtures
    /// that want a permanently disabled (no-op) registry. The returned
    /// registry passes through `park()` calls as drops and never holds
    /// any state.
    pub(crate) fn new_disabled(metrics: Arc<Metrics>) -> Self {
        Self::new(ResumptionConfig::defaults_disabled(), metrics)
    }

    pub(crate) fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// This server's cluster identity, if configured. Edge routing uses it to
    /// decode the shard embedded in a resume id and decide local-vs-relay.
    /// `None` when the server is not part of a cluster.
    pub(crate) fn cluster_identity(&self) -> Option<&ClusterIdentity> {
        self.cluster.as_ref()
    }

    /// Whether the v2 Symmetric Downlink Replay protocol is enabled
    /// server-side: requires both the parent feature on and a
    /// non-zero ring capacity. Used by header-parsing + capability
    /// echo paths to gate v2 advertisement. See
    /// `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay (v2).
    pub(crate) fn symmetric_replay_enabled(&self) -> bool {
        self.config.symmetric_replay_enabled()
    }

    /// Per-session downlink ring buffer capacity in bytes. `0` means
    /// v2 is off. Used by relay paths that allocate the ring at
    /// session-handshake time.
    #[allow(dead_code)] // wired by phases 4-6 (per-carrier capture+emit).
    pub(crate) fn downlink_buffer_bytes(&self) -> usize {
        self.config.downlink_buffer_bytes
    }

    /// Mints a fresh server-issued Session ID without registering anything.
    /// The ID is committed to the registry only when [`Self::park`] is called.
    pub(crate) fn mint_session_id(&self) -> Option<SessionId> {
        if !self.enabled() {
            return None;
        }
        let minted = match &self.cluster {
            Some(identity) => {
                SessionId::random_with_shard(&self.rng, &identity.key, identity.shard)
            },
            None => SessionId::random(&self.rng),
        };
        match minted {
            Ok(id) => Some(id),
            Err(error) => {
                warn!(?error, "csprng failure minting session id; resumption unavailable");
                None
            },
        }
    }

    /// Reserves `id` for an imminent park, returning an RAII guard the parking
    /// side holds across its reader harvest (which awaits). While the guard is
    /// live, a concurrent [`Self::take_for_resume`] for `id` that finds no
    /// committed entry waits on the reservation rather than missing. Dropping
    /// the guard — whether the park committed or was abandoned — clears the
    /// reservation and wakes any waiters, which then re-check `by_id` (a hit if
    /// the park landed, a miss otherwise).
    ///
    /// A no-op when resumption is disabled (nothing is ever committed, so there
    /// is nothing to race), matching `park`'s early drop.
    pub(crate) fn reserve_park(&self, id: SessionId) -> ParkReservation<'_> {
        if self.enabled() {
            // A duplicate reservation for the same id (e.g. an overlapping
            // teardown) simply shares the slot; the last guard dropped clears
            // it. `entry`+`or_insert` keeps a single Notify per id so waiters
            // and the committing park agree on which channel to signal.
            self.reservations.entry(id).or_insert_with(|| Arc::new(Notify::new()));
        }
        ParkReservation { registry: self, id }
    }

    /// Parks an upstream state. The caller MUST hold a freshly minted
    /// Session ID or one that the client previously received and is reusing.
    pub(crate) fn park(&self, id: SessionId, parked: Parked) {
        if !self.enabled() {
            // Parked payload (sockets, guards) is dropped here, which is
            // exactly the same as the legacy path.
            drop(parked);
            return;
        }
        let kind = parked.kind();
        let owner = match &parked {
            Parked::Tcp(tcp) => Arc::clone(&tcp.owner),
            Parked::VlessUdpSingle(udp) => Arc::clone(&udp.owner),
            Parked::VlessMux(mux) => Arc::clone(&mux.owner),
            Parked::SsUdpStream(stream) => Arc::clone(&stream.owner),
        };
        let deadline = Instant::now() + self.ttl_for_kind(kind);

        // Per-user cap: evict the oldest of this user's entries if at limit.
        let mut to_drop: Option<ParkedEntry> = None;
        {
            let entry = self
                .per_user
                .entry(Arc::clone(&owner))
                .or_insert_with(|| Mutex::new(Vec::with_capacity(self.config.orphan_per_user_cap)));
            let mut list = entry.lock();
            if list.len() >= self.config.orphan_per_user_cap
                && let Some(oldest) = list.first().copied()
            {
                list.remove(0);
                if let Some((_, evicted)) = self.by_id.remove(&oldest) {
                    self.metrics
                        .record_orphan_evicted(evicted.parked.kind(), "per_user_cap");
                    debug!(?oldest, owner = %owner, "evicted orphan due to per-user cap");
                    to_drop = Some(evicted);
                }
            }
            list.push(id);
        }
        // Drop the evicted payload (sockets etc.) outside the lock.
        drop(to_drop);

        // Global cap: best-effort one-shot eviction by oldest deadline.
        if self.by_id.len() >= self.config.orphan_global_cap
            && let Some(victim) = self.find_oldest_globally()
            && let Some((victim_id, victim_entry)) = self.by_id.remove(&victim)
        {
            if let Some(per_user) = self.per_user.get(&victim_entry.owner) {
                per_user.lock().retain(|x| *x != victim_id);
            }
            self.metrics
                .record_orphan_evicted(victim_entry.parked.kind(), "global_cap");
            debug!(victim = ?victim_id, "evicted orphan due to global cap");
            drop(victim_entry);
        }

        self.by_id.insert(id, ParkedEntry { owner, deadline, parked });
        self.metrics.record_orphan_parked(kind);
        self.refresh_kind_gauge(kind);
    }

    /// Attempts to resume the named session for an authenticated user.
    /// On a hit, the entry is removed from the registry and ownership
    /// of the upstream state transfers to the caller.
    ///
    /// If no committed entry exists but a park is *in flight* for this id (a
    /// reservation from [`Self::reserve_park`]), waits for that park to land or
    /// be abandoned before concluding a miss — otherwise a client redial that
    /// races the park's reader harvest would miss its own still-parking session
    /// and lose the mid-stream bytes. The wait is bounded by [`RESERVATION_WAIT`].
    pub(crate) async fn take_for_resume(
        &self,
        id: SessionId,
        authenticated_user: &str,
    ) -> ResumeOutcome {
        if !self.enabled() {
            return ResumeOutcome::Miss(ResumeMiss::Disabled);
        }
        // Fast path: a committed entry is already present.
        if let Some(outcome) = self.try_take_committed(id, authenticated_user) {
            return outcome;
        }
        // No committed entry yet. If a park is in flight for this id, wait for
        // it before declaring a miss — this is the race fix.
        if let Some(notify) = self.reservations.get(&id).map(|e| Arc::clone(e.value())) {
            // Arm the wait *before* re-checking the reservation, so a
            // `notify_waiters()` fired by the committing/abandoning park between
            // our lookup and our await is not lost (`Notify::notified` only
            // observes wakes registered from this point on).
            let notified = notify.notified();
            if self.reservations.contains_key(&id) {
                let _ = tokio::time::timeout(RESERVATION_WAIT, notified).await;
            }
        }
        // Final check: the park may have committed during the wait. A committed
        // entry stays in `by_id` until taken, so this never misses a landed park.
        if let Some(outcome) = self.try_take_committed(id, authenticated_user) {
            return outcome;
        }
        self.metrics
            .record_orphan_resume_miss(ResumeMiss::Unknown.metric_reason());
        ResumeOutcome::Miss(ResumeMiss::Unknown)
    }

    /// Takes an already-committed entry synchronously. `None` means nothing is
    /// indexed by `id` (the async caller may then wait on an in-flight
    /// reservation); `Some` is a definitive outcome — a hit, a TTL-expired
    /// miss, or an owner mismatch. Records the hit / eviction / mismatch metrics
    /// inline; the plain "unknown" miss is left to the caller so an in-flight
    /// park is not counted as a miss before it has had a chance to land.
    fn try_take_committed(&self, id: SessionId, authenticated_user: &str) -> Option<ResumeOutcome> {
        let (_, entry) = self.by_id.remove(&id)?;
        if entry.deadline <= Instant::now() {
            self.detach_from_per_user(&entry.owner, &id);
            let kind = entry.parked.kind();
            self.metrics.record_orphan_evicted(kind, "ttl_expired");
            self.metrics
                .record_orphan_resume_miss(ResumeMiss::Unknown.metric_reason());
            self.refresh_kind_gauge(kind);
            drop(entry);
            return Some(ResumeOutcome::Miss(ResumeMiss::Unknown));
        }
        if entry.owner.as_ref() != authenticated_user {
            // Reinsert and report owner mismatch internally. The same ID
            // may still be claimed by its rightful owner before TTL.
            let owner_for_log = Arc::clone(&entry.owner);
            self.by_id.insert(id, entry);
            warn!(
                attempted_by = %authenticated_user,
                rightful_owner = %owner_for_log,
                "resume rejected due to owner mismatch (security event)"
            );
            self.metrics
                .record_orphan_resume_miss(ResumeMiss::OwnerMismatch.metric_reason());
            return Some(ResumeOutcome::Miss(ResumeMiss::OwnerMismatch));
        }
        self.detach_from_per_user(&entry.owner, &id);
        let kind = entry.parked.kind();
        self.metrics.record_orphan_resume_hit(kind);
        self.refresh_kind_gauge(kind);
        Some(ResumeOutcome::Hit(entry.parked))
    }

    /// Sweeps expired entries. Called by the periodic maintenance task.
    /// Returns the number of entries evicted in this sweep.
    pub(crate) fn sweep_expired(&self) -> usize {
        if !self.enabled() {
            return 0;
        }
        let now = Instant::now();
        let mut expired = Vec::new();
        for entry in self.by_id.iter() {
            if entry.value().deadline <= now {
                expired.push(*entry.key());
            }
        }
        let count = expired.len();
        for id in expired {
            if let Some((_, entry)) = self.by_id.remove(&id) {
                let kind = entry.parked.kind();
                self.detach_from_per_user(&entry.owner, &id);
                self.metrics.record_orphan_evicted(kind, "ttl_expired");
                drop(entry);
            }
        }
        if count > 0 {
            for kind in Parked::all_kinds() {
                self.refresh_kind_gauge(kind);
            }
        }
        count
    }

    fn ttl_for_kind(&self, kind: &'static str) -> Duration {
        match kind {
            "tcp" => self.config.orphan_ttl_tcp,
            _ => self.config.orphan_ttl_udp,
        }
    }

    fn detach_from_per_user(&self, owner: &Arc<str>, id: &SessionId) {
        if let Some(per_user) = self.per_user.get(owner) {
            per_user.lock().retain(|x| x != id);
        }
    }

    fn refresh_kind_gauge(&self, kind: &'static str) {
        let count = self
            .by_id
            .iter()
            .filter(|entry| entry.value().parked.kind() == kind)
            .count();
        self.metrics.set_orphan_current(kind, count as f64);
        // The v2 downlink ring only lives on TCP entries, but a UDP
        // park can still evict a TCP entry by the global cap — so
        // refresh the bytes gauge unconditionally here, not just when
        // `kind == "tcp"`. Cheap (one O(N) walk) and avoids a separate
        // sampler.
        self.refresh_downlink_buf_gauge();
    }

    /// Walks every parked TCP entry, sums the bytes currently retained
    /// in its v2 downlink ring (if allocated), and publishes the total
    /// on the `outline_ss_orphan_downlink_buf_bytes` gauge. O(N) in the
    /// number of parked TCP sessions and grabs each ring's `parking_lot`
    /// mutex briefly; called from event handlers that are already O(N)
    /// or rarer.
    fn refresh_downlink_buf_gauge(&self) {
        let total: u64 = self
            .by_id
            .iter()
            .filter_map(|entry| match &entry.value().parked {
                Parked::Tcp(tcp) => tcp
                    .downlink_ring
                    .as_ref()
                    .map(|ring| ring.lock().buffered_bytes() as u64),
                _ => None,
            })
            .sum();
        self.metrics.set_orphan_downlink_buf_bytes(total as f64);
    }

    /// Returns the Session ID with the earliest deadline. O(N), but only
    /// called when the global cap has been hit.
    fn find_oldest_globally(&self) -> Option<SessionId> {
        let mut oldest: Option<(SessionId, Instant)> = None;
        for entry in self.by_id.iter() {
            let deadline = entry.value().deadline;
            if oldest.is_none_or(|(_, d)| deadline < d) {
                oldest = Some((*entry.key(), deadline));
            }
        }
        oldest.map(|(id, _)| id)
    }

    /// Total parked count. Test/inspection only.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }
}

/// RAII reservation guard from [`OrphanRegistry::reserve_park`]. The parking
/// side holds it across the reader harvest; dropping it — after a successful
/// `park` or on any abandon path — clears the reservation and wakes any resume
/// waiting on this id, which then re-checks `by_id`.
#[must_use]
pub(crate) struct ParkReservation<'a> {
    registry: &'a OrphanRegistry,
    id: SessionId,
}

impl Drop for ParkReservation<'_> {
    fn drop(&mut self) {
        // Clear the reservation and wake every current waiter. Remove *before*
        // notifying so a woken waiter observes `contains_key == false` and does
        // not re-arm. Waiters then re-check `by_id`: a hit if `park` committed
        // before this drop, a miss otherwise. `notify_waiters` leaves no permit,
        // which is correct — once the reservation is gone a later resume takes
        // the committed fast path or waits on a fresh reservation instead.
        //
        // A no-op when the id was never inserted (resumption disabled) or when
        // an overlapping teardown's guard already cleared the shared slot.
        if let Some((_, notify)) = self.registry.reservations.remove(&self.id) {
            notify.notify_waiters();
        }
    }
}

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
