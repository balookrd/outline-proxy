use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::sync::{Mutex, OnceCell};
use tracing::debug;

use crate::{
    clock,
    crypto::{UdpSession, UserKey},
    fwmark::apply_fwmark_if_needed,
    metrics::Metrics,
    outbound::OutboundIpv6,
};

use super::{
    entry::{NatEntry, NatKey, random_session_id},
    reader::{NatReaderCtx, nat_reader_task},
    socket::bind_nat_udp_socket,
};

/// Process-wide NAT table.  Shared via `Arc` in `AppState`.
pub(crate) struct NatTable {
    entries: DashMap<NatKey, Arc<OnceCell<Arc<NatEntry>>>>,
    idle_timeout: Duration,
    outbound_ipv6: Option<Arc<OutboundIpv6>>,
}

impl NatTable {
    #[cfg(test)]
    pub(crate) fn new(idle_timeout: Duration) -> Arc<Self> {
        Self::with_outbound_ipv6(idle_timeout, None)
    }

    pub(crate) fn with_outbound_ipv6(
        idle_timeout: Duration,
        outbound_ipv6: Option<Arc<OutboundIpv6>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            idle_timeout,
            outbound_ipv6,
        })
    }

    /// Returns the existing NAT entry for `key`, or creates a new one: binds a
    /// UDP socket, applies `fwmark` if set, and starts a background reader task
    /// that delivers upstream responses to the registered client session.
    pub(crate) async fn get_or_create(
        &self,
        key: NatKey,
        user: &UserKey,
        udp_session: UdpSession,
        metrics: Arc<Metrics>,
    ) -> Result<Arc<NatEntry>> {
        // DashMap shard lock is held only for the insert/lookup, then dropped
        // before any `.await` — the OnceCell deduplicates concurrent creation.
        let cell = Arc::clone(
            self.entries
                .entry(key.clone())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .value(),
        );

        // On error the cell stays uninitialised; evict_idle drops such cells
        // without counting them as evictions (they never incremented the
        // active-entries metric), so no second lock is needed to clean up.
        let create_user = user.clone();
        let outbound = self.outbound_ipv6.clone();
        cell.get_or_try_init(|| async move {
            Self::create_entry(&key, create_user, udp_session, metrics, outbound).await
        })
        .await
        .map(Arc::clone)
    }

    async fn create_entry(
        key: &NatKey,
        user: UserKey,
        udp_session: UdpSession,
        metrics: Arc<Metrics>,
        outbound_ipv6: Option<Arc<OutboundIpv6>>,
    ) -> Result<Arc<NatEntry>> {
        let socket = bind_nat_udp_socket(key.target, outbound_ipv6.as_deref())
            .with_context(|| format!("failed to bind NAT UDP socket for {}", key.target))?;
        apply_fwmark_if_needed(&socket, key.fwmark)
            .with_context(|| format!("failed to apply fwmark {:?} to NAT socket", key.fwmark))?;
        let socket = Arc::new(socket);

        let active = Arc::new(Mutex::new(None));
        let last_active_secs = Arc::new(AtomicU64::new(clock::current_unix_secs()));
        let next_packet_id = Arc::new(AtomicU64::new(0));
        let server_session_id = match udp_session {
            UdpSession::Legacy => None,
            UdpSession::Aes2022 { .. } | UdpSession::Chacha2022 { .. } => {
                Some(random_session_id()?)
            },
        };

        let reader_task = tokio::spawn(nat_reader_task(NatReaderCtx {
            socket: Arc::clone(&socket),
            active: Arc::clone(&active),
            user: user.clone(),
            target: key.target,
            server_session_id,
            metrics: Arc::clone(&metrics),
            last_active: Arc::clone(&last_active_secs),
            next_packet_id: Arc::clone(&next_packet_id),
        }));

        let entry = NatEntry::new(socket, active, last_active_secs, reader_task);
        debug!(
            user = %key.user_id,
            target = %key.target,
            "created UDP NAT entry"
        );
        metrics.record_udp_nat_entry_created();
        Ok(entry)
    }

    /// Current number of active NAT entries (informational).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries
            .iter()
            .filter(|r| r.value().get().is_some())
            .count()
    }

    /// Remove entries that have had no outbound traffic for longer than
    /// `self.idle_timeout`.  The reader task for each evicted entry is aborted
    /// when the `Arc<NatEntry>` refcount reaches zero.
    pub(crate) fn evict_idle(&self, metrics: &Metrics) {
        let threshold = clock::current_unix_secs().saturating_sub(self.idle_timeout.as_secs());
        let mut evicted = 0usize;
        self.entries.retain(|_, cell| match cell.get() {
            Some(entry) => {
                let keep = entry.last_active_secs().load(Ordering::Relaxed) >= threshold;
                if !keep {
                    evicted += 1;
                }
                keep
            },
            None => false,
        });
        if evicted > 0 {
            metrics.record_udp_nat_entries_evicted(evicted);
            debug!(
                evicted,
                remaining = self.entries.len(),
                "evicted idle UDP NAT entries"
            );
        }
    }
}
