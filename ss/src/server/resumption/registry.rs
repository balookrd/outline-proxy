//! In-memory registry of parked upstream sessions awaiting cross-transport resume.
//!
//! All entries live in process memory; nothing survives a restart. See
//! `docs/SESSION-RESUMPTION.md` for the lifecycle model.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use parking_lot::Mutex;
use ring::rand::SystemRandom;
use tracing::{debug, warn};

use crate::metrics::Metrics;

use super::{
    config::ResumptionConfig,
    parked::Parked,
    session_id::SessionId,
};

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
    /// Per-user index for cap enforcement and bulk eviction. The Mutex
    /// scope is narrow and contention is bounded by `orphan_per_user_cap`
    /// (4 by default), so a parking_lot mutex is preferred over a per-key
    /// async lock.
    per_user: DashMap<Arc<str>, Mutex<Vec<SessionId>>>,
    metrics: Arc<Metrics>,
}

impl OrphanRegistry {
    pub(crate) fn new(config: ResumptionConfig, metrics: Arc<Metrics>) -> Self {
        Self {
            config,
            rng: SystemRandom::new(),
            by_id: DashMap::new(),
            per_user: DashMap::new(),
            metrics,
        }
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
        match SessionId::random(&self.rng) {
            Ok(id) => Some(id),
            Err(error) => {
                warn!(?error, "csprng failure minting session id; resumption unavailable");
                None
            },
        }
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

        self.by_id
            .insert(id, ParkedEntry { owner, deadline, parked });
        self.metrics.record_orphan_parked(kind);
        self.refresh_kind_gauge(kind);
    }

    /// Attempts to resume the named session for an authenticated user.
    /// On a hit, the entry is removed from the registry and ownership
    /// of the upstream state transfers to the caller.
    pub(crate) fn take_for_resume(
        &self,
        id: SessionId,
        authenticated_user: &str,
    ) -> ResumeOutcome {
        if !self.enabled() {
            return ResumeOutcome::Miss(ResumeMiss::Disabled);
        }
        let Some((_, entry)) = self.by_id.remove(&id) else {
            self.metrics
                .record_orphan_resume_miss(ResumeMiss::Unknown.metric_reason());
            return ResumeOutcome::Miss(ResumeMiss::Unknown);
        };
        if entry.deadline <= Instant::now() {
            self.detach_from_per_user(&entry.owner, &id);
            let kind = entry.parked.kind();
            self.metrics.record_orphan_evicted(kind, "ttl_expired");
            self.metrics
                .record_orphan_resume_miss(ResumeMiss::Unknown.metric_reason());
            self.refresh_kind_gauge(kind);
            drop(entry);
            return ResumeOutcome::Miss(ResumeMiss::Unknown);
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
            return ResumeOutcome::Miss(ResumeMiss::OwnerMismatch);
        }
        self.detach_from_per_user(&entry.owner, &id);
        let kind = entry.parked.kind();
        self.metrics.record_orphan_resume_hit(kind);
        self.refresh_kind_gauge(kind);
        ResumeOutcome::Hit(entry.parked)
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

#[cfg(test)]
#[path = "tests/registry.rs"]
mod tests;
