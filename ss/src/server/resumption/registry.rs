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
    /// Resume failed; the inner reason is observable via metrics but
    /// callers do not currently switch on it (the only behavioural
    /// difference between miss reasons is the metric reason label).
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
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use tokio::net::{TcpListener, TcpStream};

    use crate::{
        config::{CipherKind, Config, H3Alpn, UserEntry},
        crypto::UserKey,
        metrics::{Metrics, Protocol},
    };

    use super::super::parked::{Parked, ParkedTcp, TcpProtocolContext};
    use super::*;

    fn test_config() -> Config {
        Config {
            listen: Some("127.0.0.1:3000".parse().unwrap()),
            ss_listen: None,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            h3_alpn: vec![H3Alpn::H3],
            metrics_listen: None,
            metrics_path: "/metrics".into(),
            prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            ws_path_vless: None,
            http_root_auth: false,
            http_root_realm: "Authorization required".into(),
            users: vec![UserEntry {
                id: "u1".into(),
                password: Some("secret".into()),
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                ws_path_vless: None,
                enabled: None,
            }],
            method: CipherKind::Chacha20IetfPoly1305,
            access_key: Default::default(),
            tuning: Default::default(),
            session_resumption: Default::default(),
            config_path: None,
            control: None,
            dashboard: None,
        }
    }

    fn enabled_config() -> ResumptionConfig {
        ResumptionConfig {
            enabled: true,
            ..ResumptionConfig::defaults_disabled()
        }
    }

    async fn loopback_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (incoming, outgoing) =
            tokio::join!(async { listener.accept().await.unwrap().0 }, TcpStream::connect(addr));
        (incoming, outgoing.unwrap())
    }

    fn make_user(id: &str) -> UserKey {
        UserKey::new(id, "secret-pass", None, CipherKind::Chacha20IetfPoly1305).unwrap()
    }

    async fn make_parked_tcp(metrics: &Arc<Metrics>, owner: &str) -> Parked {
        let (a, _b) = loopback_tcp_pair().await;
        let (reader, writer) = a.into_split();
        let user = make_user(owner);
        let user_id = user.id_arc();
        Parked::Tcp(ParkedTcp {
            upstream_writer: writer,
            upstream_reader: reader,
            target_display: Arc::from("example.com:443"),
            protocol: Protocol::Http2,
            owner: Arc::clone(&user_id),
            protocol_context: TcpProtocolContext::Ss(user),
            user_counters: metrics.user_counters(&user_id),
            upstream_guard: metrics.open_tcp_upstream_connection(user_id, Protocol::Http2),
        })
    }

    #[tokio::test]
    async fn disabled_registry_drops_park_silently() {
        let metrics = Metrics::new(&test_config());
        let registry = OrphanRegistry::new(ResumptionConfig::defaults_disabled(), metrics.clone());
        assert!(!registry.enabled());
        assert!(registry.mint_session_id().is_none());
        let parked = make_parked_tcp(&metrics, "u1").await;
        registry.park(SessionId::from_bytes([0u8; 16]), parked);
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn park_then_take_returns_payload_for_owner() {
        let metrics = Metrics::new(&test_config());
        let registry = OrphanRegistry::new(enabled_config(), metrics.clone());
        let id = registry.mint_session_id().unwrap();
        let parked = make_parked_tcp(&metrics, "u1").await;
        registry.park(id, parked);
        assert_eq!(registry.len(), 1);

        let outcome = registry.take_for_resume(id, "u1");
        assert!(matches!(outcome, ResumeOutcome::Hit(Parked::Tcp(_))));
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn take_with_wrong_owner_keeps_entry_and_reports_mismatch() {
        let metrics = Metrics::new(&test_config());
        let registry = OrphanRegistry::new(enabled_config(), metrics.clone());
        let id = registry.mint_session_id().unwrap();
        let parked = make_parked_tcp(&metrics, "alice").await;
        registry.park(id, parked);

        let outcome = registry.take_for_resume(id, "mallory");
        assert!(matches!(
            outcome,
            ResumeOutcome::Miss(ResumeMiss::OwnerMismatch)
        ));
        // The entry stays parked so its rightful owner can still claim it.
        assert_eq!(registry.len(), 1);

        let outcome = registry.take_for_resume(id, "alice");
        assert!(matches!(outcome, ResumeOutcome::Hit(Parked::Tcp(_))));
    }

    #[tokio::test]
    async fn unknown_id_misses() {
        let metrics = Metrics::new(&test_config());
        let registry = OrphanRegistry::new(enabled_config(), metrics);
        let outcome = registry.take_for_resume(SessionId::from_bytes([7u8; 16]), "anyone");
        assert!(matches!(outcome, ResumeOutcome::Miss(ResumeMiss::Unknown)));
    }

    #[tokio::test]
    async fn per_user_cap_evicts_oldest() {
        let metrics = Metrics::new(&test_config());
        let cfg = ResumptionConfig {
            enabled: true,
            orphan_per_user_cap: 2,
            ..ResumptionConfig::defaults_disabled()
        };
        let registry = OrphanRegistry::new(cfg, metrics.clone());
        let id1 = registry.mint_session_id().unwrap();
        let id2 = registry.mint_session_id().unwrap();
        let id3 = registry.mint_session_id().unwrap();
        registry.park(id1, make_parked_tcp(&metrics, "u1").await);
        registry.park(id2, make_parked_tcp(&metrics, "u1").await);
        registry.park(id3, make_parked_tcp(&metrics, "u1").await);

        assert_eq!(registry.len(), 2, "oldest entry must have been evicted");
        assert!(matches!(
            registry.take_for_resume(id1, "u1"),
            ResumeOutcome::Miss(ResumeMiss::Unknown)
        ));
        assert!(matches!(
            registry.take_for_resume(id2, "u1"),
            ResumeOutcome::Hit(_)
        ));
        assert!(matches!(
            registry.take_for_resume(id3, "u1"),
            ResumeOutcome::Hit(_)
        ));
    }

    #[tokio::test]
    async fn sweep_drops_expired_entries() {
        let metrics = Metrics::new(&test_config());
        let cfg = ResumptionConfig {
            enabled: true,
            orphan_ttl_tcp: Duration::from_millis(20),
            ..ResumptionConfig::defaults_disabled()
        };
        let registry = OrphanRegistry::new(cfg, metrics.clone());
        let id = registry.mint_session_id().unwrap();
        registry.park(id, make_parked_tcp(&metrics, "u1").await);
        assert_eq!(registry.len(), 1);

        tokio::time::sleep(Duration::from_millis(40)).await;
        let removed = registry.sweep_expired();
        assert_eq!(removed, 1);
        assert_eq!(registry.len(), 0);
    }
}
