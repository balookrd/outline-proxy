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
    _permit: OwnedSemaphorePermit,
}

impl PooledRelay {
    /// Splits into the owned stream halves and the pool permit. The caller
    /// must keep the permit alive for the relay's lifetime (it releases the
    /// concurrency slot on drop).
    pub(in crate::server) fn into_parts(
        self,
    ) -> (quinn::SendStream, quinn::RecvStream, OwnedSemaphorePermit) {
        (self.stream.send, self.stream.recv, self._permit)
    }
}

/// Connections to peer homes, dialed on demand and reused.
pub(in crate::server) struct MeshPeerPool {
    endpoint: MeshEndpoint,
    peers: HashMap<ShardId, SocketAddr>,
    conns: Mutex<HashMap<ShardId, Connection>>,
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
        Ok(PooledRelay { stream, _permit: permit })
    }

    /// Returns a live connection to `addr` for `shard`, dialing if there is no
    /// cached connection or the cached one has closed.
    async fn connection_for(&self, shard: ShardId, addr: SocketAddr) -> Result<Connection> {
        let mut guard = self.conns.lock().await;
        if let Some(conn) = guard.get(&shard)
            && conn.close_reason().is_none()
        {
            return Ok(conn.clone());
        }
        let conn = self
            .endpoint
            .connect(addr)
            .await
            .with_context(|| format!("dialing mesh peer shard {}", shard.get()))?;
        guard.insert(shard, conn.clone());
        Ok(conn)
    }
}

#[cfg(test)]
#[path = "tests/peer_pool.rs"]
mod tests;
