//! Pool of mesh connections to peer homes, keyed by shard.
//!
//! An edge relaying a session looks up the home's address by shard, reuses a
//! live QUIC connection (or dials one, redialing if the cached one died), and
//! opens a relay stream on it. Concurrent relay streams are bounded by a
//! semaphore so a burst cannot exhaust memory/handles (the "bounded resources"
//! invariant); the permit rides the [`MeshStream`] and releases on drop.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use outline_wire::cluster::ShardId;
use quinn::Connection;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use super::endpoint::{MeshEndpoint, MeshStream, open_relay_stream};
use super::frame::OpenHeader;

/// A relay stream plus the pool permit that keeps it counted against the
/// concurrency cap until it is dropped.
pub(in crate::server) struct PooledRelay {
    pub(in crate::server) stream: MeshStream,
    /// The mesh connection the stream rides, so the edge can send out-of-band
    /// control datagrams (THROTTLE_HINT) on it alongside the relay stream.
    conn: Connection,
    _permit: OwnedSemaphorePermit,
}

impl PooledRelay {
    /// A handle to the mesh connection carrying this relay, for sending control
    /// datagrams. Cloneable and cheap (quinn `Connection` is `Arc`-backed).
    pub(in crate::server) fn connection(&self) -> Connection {
        self.conn.clone()
    }

    /// Splits into the owned stream halves and the pool permit. The caller
    /// must keep the permit alive for the relay's lifetime (it releases the
    /// concurrency slot on drop).
    pub(in crate::server) fn into_parts(
        self,
    ) -> (quinn::SendStream, quinn::RecvStream, OwnedSemaphorePermit) {
        (self.stream.send, self.stream.recv, self._permit)
    }
}

/// One shard's cached connection. Held behind its own lock so a dial to a dead
/// peer only serializes further relays to *that* shard.
type ConnSlot = Arc<Mutex<Option<Connection>>>;

/// Connections to peer homes, dialed on demand and reused.
pub(in crate::server) struct MeshPeerPool {
    endpoint: MeshEndpoint,
    peers: HashMap<ShardId, SocketAddr>,
    /// Maps a shard to its connection slot. The outer lock is only ever held
    /// long enough to clone the slot handle — never across a dial.
    conns: Mutex<HashMap<ShardId, ConnSlot>>,
    stream_permits: Arc<Semaphore>,
}

impl MeshPeerPool {
    /// Builds a pool over `endpoint` with the shard→address routing table and a
    /// cap on concurrent relay streams.
    pub(in crate::server) fn new(
        endpoint: MeshEndpoint,
        peers: HashMap<ShardId, SocketAddr>,
        max_concurrent_streams: usize,
    ) -> Self {
        Self {
            endpoint,
            peers,
            conns: Mutex::new(HashMap::new()),
            stream_permits: Arc::new(Semaphore::new(max_concurrent_streams)),
        }
    }

    /// Opens a relay stream to the home that owns `shard`, writing `header`
    /// first. Reuses a live connection or dials (and caches) a fresh one.
    /// Returns an error if the shard is unknown, the cap is exhausted, or the
    /// dial/handshake fails — the caller degrades to a fresh local session.
    pub(in crate::server) async fn open_relay(
        &self,
        shard: ShardId,
        header: &OpenHeader,
    ) -> Result<PooledRelay> {
        let Some(&addr) = self.peers.get(&shard) else {
            bail!("no mesh peer configured for shard {}", shard.get());
        };
        let permit = Arc::clone(&self.stream_permits)
            .try_acquire_owned()
            .context("mesh relay stream cap exhausted")?;
        let conn = self.connection_for(shard, addr).await?;
        let stream = open_relay_stream(&conn, header).await?;
        Ok(PooledRelay { stream, conn, _permit: permit })
    }

    /// Returns a live connection to `addr` for `shard`, dialing if there is no
    /// cached connection or the cached one has closed.
    ///
    /// The dial happens under the shard's own slot lock, not the pool-wide one:
    /// an unreachable peer stalls its handshake for the mesh idle timeout, and
    /// holding the shared map across that would freeze relays to every other
    /// shard. Concurrent callers for the *same* shard still serialize, so a
    /// burst dials once and the rest reuse the result.
    async fn connection_for(&self, shard: ShardId, addr: SocketAddr) -> Result<Connection> {
        let slot: ConnSlot = {
            let mut guard = self.conns.lock().await;
            Arc::clone(guard.entry(shard).or_insert_with(|| Arc::new(Mutex::new(None))))
        };
        let mut cached = slot.lock().await;
        if let Some(conn) = cached.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }
        let conn = self
            .endpoint
            .connect(addr)
            .await
            .with_context(|| format!("dialing mesh peer shard {}", shard.get()))?;
        *cached = Some(conn.clone());
        Ok(conn)
    }
}

#[cfg(test)]
#[path = "tests/peer_pool.rs"]
mod tests;
