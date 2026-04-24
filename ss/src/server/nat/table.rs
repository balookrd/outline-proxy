use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result};
use dashmap::DashMap;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, OnceCell},
};
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
                    .random_addr()
                    .context("failed to generate random outbound IPv6 address")?;
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
        let bind_addr: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
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
            Arc::clone(
                self.entries
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(OnceCell::new()))
                    .value(),
            )
        };

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
        self.entries.iter().filter(|r| r.value().get().is_some()).count()
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
            debug!(evicted, remaining = self.entries.len(), "evicted idle UDP NAT entries");
        }
    }
}
