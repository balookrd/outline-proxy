use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use dashmap::{DashMap, mapref::entry::Entry};
use parking_lot::Mutex;
use tokio::{net::UdpSocket, sync::OnceCell};
use tracing::debug;

use crate::{
    clock,
    crypto::{UdpCipherMode, UserKey},
    fwmark::apply_fwmark_if_needed,
    metrics::Metrics,
    outbound::{OutboundIpv6, set_ipv6_freebind},
};

use super::{
    entry::{NatEntry, NatKey, random_session_id},
    reader::{NatReaderCtx, nat_reader_task},
};

/// Create the NAT upstream UDP socket. When `outbound_ipv6` is configured and
/// the target is IPv6, the socket is bound to a random address from the pool
/// (with `IPV6_FREEBIND` to allow non-local bind); otherwise it falls back to
/// the kernel default wildcard bind, matching legacy behaviour. Interface
/// mode may return no usable address (e.g. interface not up yet) — in that
/// case we also fall back to the wildcard bind rather than fail the datagram.
pub(crate) fn bind_nat_udp_socket(
    target: SocketAddr,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<UdpSocket> {
    use socket2::{Domain, SockAddr, Socket, Type};

    let source = if target.is_ipv6() {
        match outbound_ipv6 {
            Some(src) => {
                let picked = src
                    .source_for(target.ip(), clock::current_unix_secs())
                    .context("failed to generate outbound IPv6 source address")?;
                if picked.is_none() {
                    tracing::debug!(
                        %target,
                        source = %src,
                        "outbound IPv6 pool is empty; NAT UDP socket falling back to wildcard bind",
                    );
                }
                picked
            },
            None => None,
        }
    } else {
        None
    };

    if source.is_none() {
        if target.is_ipv6() {
            // IPv6 wildcard: build via socket2 so we can request a stable
            // public source (no-op under host rotation / when disabled) before
            // the kernel picks one at send time. Mirrors the TCP outbound path.
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(socket2::Protocol::UDP))
                .context("failed to create NAT UDP socket")?;
            outline_net::apply_prefer_public_ipv6_src(&socket);
            let bind_addr: SocketAddr = "[::]:0".parse().unwrap();
            socket
                .bind(&SockAddr::from(bind_addr))
                .with_context(|| format!("failed to bind NAT UDP socket on {bind_addr}"))?;
            socket
                .set_nonblocking(true)
                .context("failed to set NAT UDP socket nonblocking")?;
            let std_socket: std::net::UdpSocket = socket.into();
            return UdpSocket::from_std(std_socket).context("failed to register NAT UDP socket");
        }
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let std_socket = std::net::UdpSocket::bind(bind_addr)
            .with_context(|| format!("failed to bind NAT UDP socket on {bind_addr}"))?;
        std_socket
            .set_nonblocking(true)
            .context("failed to set NAT UDP socket nonblocking")?;
        return UdpSocket::from_std(std_socket).context("failed to register NAT UDP socket");
    }

    let source = source.expect("checked above");
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create NAT UDP socket")?;
    set_ipv6_freebind(&socket).context("failed to set IPV6_FREEBIND on NAT UDP socket")?;
    let bind_addr = SocketAddr::V6(std::net::SocketAddrV6::new(source, 0, 0, 0));
    socket
        .bind(&SockAddr::from(bind_addr))
        .with_context(|| format!("failed to bind NAT UDP socket {bind_addr}"))?;
    socket
        .set_nonblocking(true)
        .context("failed to set NAT UDP socket nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("failed to register NAT UDP socket")
}

/// Ceilings on the NAT table. Both are entry counts and `0` disables the
/// corresponding cap. See `TuningProfile::udp_nat_max_entries` and
/// `TuningProfile::udp_nat_max_entries_per_user`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NatLimits {
    /// Upper bound on live entries process-wide.
    pub max_entries: usize,
    /// Upper bound on live entries owned by a single authenticated user, so one
    /// tenant cannot claim the whole table and starve the others.
    pub max_entries_per_user: usize,
}

/// Process-wide NAT table.  Shared via `Arc` in `AppState`.
pub(crate) struct NatTable {
    entries: DashMap<NatKey, Arc<OnceCell<Arc<NatEntry>>>>,
    idle_timeout: Duration,
    limits: NatLimits,
    /// Live entry count per user, maintained alongside `entries` so the
    /// per-user cap costs a shard lookup instead of a full table scan.
    /// A user's counter is removed once it drops to zero.
    per_user: DashMap<Arc<str>, usize>,
    outbound_ipv6: Option<Arc<OutboundIpv6>>,
}

impl NatTable {
    #[cfg(test)]
    pub(crate) fn new(idle_timeout: Duration) -> Arc<Self> {
        // Tests default to an unbounded table; the caps have dedicated coverage.
        Self::with_outbound_ipv6(idle_timeout, NatLimits::default(), None)
    }

    pub(crate) fn with_outbound_ipv6(
        idle_timeout: Duration,
        limits: NatLimits,
        outbound_ipv6: Option<Arc<OutboundIpv6>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            idle_timeout,
            limits,
            per_user: DashMap::new(),
            outbound_ipv6,
        })
    }

    /// Returns the existing NAT entry for `key` if one is registered;
    /// `None` otherwise. Unlike [`Self::get_or_create`] this never
    /// allocates a fresh socket, so it is the right primitive for the
    /// SS-UDP-over-WS resume / park paths that only want to inspect
    /// already-live state.
    pub(crate) fn try_get(&self, key: &NatKey) -> Option<Arc<NatEntry>> {
        self.entries.get(key).and_then(|cell| cell.get().cloned())
    }

    /// Whether a live entry is registered for `key`. Same lookup as
    /// [`Self::try_get`] without cloning the `Arc` — used by callers that only
    /// need liveness, e.g. the SS-UDP stream reconciling the set of NAT keys it
    /// still owns against the entries that idle eviction has since dropped.
    pub(crate) fn contains(&self, key: &NatKey) -> bool {
        self.entries.get(key).is_some_and(|cell| cell.get().is_some())
    }

    /// Returns the existing NAT entry for `key`, or creates a new one: binds a
    /// UDP socket, applies `fwmark` if set, and starts a background reader task
    /// that delivers upstream responses to the registered client session.
    pub(crate) async fn get_or_create(
        &self,
        key: NatKey,
        user: &UserKey,
        udp_session: UdpCipherMode,
        metrics: Arc<Metrics>,
    ) -> Result<Arc<NatEntry>> {
        // Fast path: read-lock the shard for an existing entry — the hot case
        // after a session's first packet. Only fall back to `entry()` (write
        // lock + key clone) when the entry is missing. The OnceCell still
        // deduplicates concurrent creation on the cold path.
        let cell = if let Some(existing) = self.entries.get(&key) {
            Arc::clone(existing.value())
        } else {
            // New key: enforce the entry cap before allocating a socket + reader
            // task. `entries.len()` counts live plus in-flight (uninitialised)
            // cells, so this is an approximate ceiling — a small overshoot under
            // a concurrent-creation race is harmless for a protective cap, and
            // `0` disables it. Existing entries are never evicted here, so a
            // full table only drops datagrams to *new* targets.
            if self.limits.max_entries > 0 && self.entries.len() >= self.limits.max_entries {
                metrics.record_udp_nat_capacity_dropped();
                bail!("UDP NAT table at capacity ({} entries)", self.limits.max_entries);
            }
            // Then the per-user share. The slot is reserved *before* the map
            // insert so two concurrent creations for the same user cannot both
            // pass the check, and handed back below if we lost the insert race.
            if !self.reserve_user_slot(&key.user_id) {
                metrics.record_udp_nat_capacity_dropped();
                bail!(
                    "UDP NAT table at per-user capacity ({} entries)",
                    self.limits.max_entries_per_user
                );
            }
            match self.entries.entry(key.clone()) {
                Entry::Occupied(occupied) => {
                    self.release_user_slot(&key.user_id);
                    Arc::clone(occupied.get())
                },
                Entry::Vacant(vacant) => {
                    Arc::clone(vacant.insert(Arc::new(OnceCell::new())).value())
                },
            }
        };

        // On error the cell stays uninitialised; evict_idle drops such cells
        // without counting them as evictions (they never incremented the
        // active-entries metric) and returns their per-user slot, so no second
        // lock is needed to clean up.
        let create_user = user.clone();
        let outbound = self.outbound_ipv6.clone();
        cell.get_or_try_init(|| async move {
            Self::create_entry(&key, create_user, udp_session, metrics, outbound).await
        })
        .await
        .map(Arc::clone)
    }

    /// Claims one per-user entry slot, returning `false` when the user is
    /// already at `max_entries_per_user`. A disabled cap always succeeds and
    /// skips the bookkeeping entirely.
    fn reserve_user_slot(&self, user: &Arc<str>) -> bool {
        let cap = self.limits.max_entries_per_user;
        if cap == 0 {
            return true;
        }
        let mut count = self.per_user.entry(Arc::clone(user)).or_insert(0);
        if *count >= cap {
            return false;
        }
        *count += 1;
        true
    }

    /// Returns a slot claimed by [`Self::reserve_user_slot`]. The counter is
    /// dropped at zero so the map stays proportional to the users that
    /// currently hold entries.
    fn release_user_slot(&self, user: &Arc<str>) {
        if self.limits.max_entries_per_user == 0 {
            return;
        }
        if let Entry::Occupied(mut occupied) = self.per_user.entry(Arc::clone(user)) {
            let count = occupied.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                occupied.remove();
            }
        }
    }

    async fn create_entry(
        key: &NatKey,
        user: UserKey,
        udp_session: UdpCipherMode,
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
            UdpCipherMode::Legacy => None,
            UdpCipherMode::Aes2022 { .. } | UdpCipherMode::Chacha2022 { .. } => {
                Some(random_session_id()?)
            },
        };

        let user_counters = metrics.user_counters(&key.user_id);
        let reader_task = tokio::spawn(nat_reader_task(NatReaderCtx {
            socket: Arc::clone(&socket),
            active: Arc::clone(&active),
            user: user.clone(),
            target: key.target,
            server_session_id,
            metrics: Arc::clone(&metrics),
            user_counters: Arc::clone(&user_counters),
            last_active: Arc::clone(&last_active_secs),
            next_packet_id: Arc::clone(&next_packet_id),
        }));

        let entry = NatEntry::new(socket, active, user_counters, last_active_secs, reader_task);
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
        self.entries.iter().filter(|r| r.value().get().is_some()).count()
    }

    /// Remove entries that have had no outbound traffic for longer than
    /// `self.idle_timeout`.  The reader task for each evicted entry is aborted
    /// when the `Arc<NatEntry>` refcount reaches zero.
    pub(crate) fn evict_idle(&self, metrics: &Metrics) {
        let threshold = clock::current_unix_secs().saturating_sub(self.idle_timeout.as_secs());
        let mut evicted = 0usize;
        // Removed keys whose per-user slot has to be handed back; skipped
        // entirely when the per-user cap is disabled. Collected during the
        // sweep and released after it, so we never take a `per_user` lock while
        // `retain` holds an `entries` shard.
        let track_users = self.limits.max_entries_per_user > 0;
        let mut released: Vec<Arc<str>> = Vec::new();
        self.entries.retain(|key, cell| {
            let keep = match cell.get() {
                Some(entry) => {
                    let keep = entry.last_active_secs().load(Ordering::Relaxed) >= threshold;
                    if !keep {
                        evicted += 1;
                    }
                    keep
                },
                None => false,
            };
            if !keep && track_users {
                released.push(Arc::clone(&key.user_id));
            }
            keep
        });
        for user in &released {
            self.release_user_slot(user);
        }
        if evicted > 0 {
            metrics.record_udp_nat_entries_evicted(evicted);
            debug!(evicted, remaining = self.entries.len(), "evicted idle UDP NAT entries");
        }
    }
}
