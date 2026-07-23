//! Idle keep-alive connections to the control APIs the dashboard proxies to.
//!
//! Without it every dashboard request pays a fresh TCP (and, on `https`
//! instances, TLS) handshake — the browser polls on a refresh interval, so that
//! is a handshake per instance per tick. The pool is deliberately small and
//! self-pruning: connections are parked per target, capped in count, and
//! discarded once closed or older than `idle_ttl`, so an idle dashboard holds
//! at most `max_idle_per_target × instances` sockets.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use parking_lot::Mutex;

/// A parked connection plus when it was parked: an upstream that silently drops
/// idle keep-alive sockets leaves a sender that still looks open, so age is the
/// only cheap guard against handing out a dead one.
struct IdleConn {
    sender: SendRequest<Full<Bytes>>,
    parked_at: Instant,
}

pub(super) struct ControlPool {
    /// Keyed by `scheme://host:port` — one bucket per upstream endpoint, so the
    /// map stays proportional to the configured instances.
    idle: Mutex<HashMap<String, Vec<IdleConn>>>,
    max_idle_per_target: usize,
    idle_ttl: Duration,
}

impl ControlPool {
    pub(super) fn new(max_idle_per_target: usize, idle_ttl: Duration) -> Self {
        Self {
            idle: Mutex::new(HashMap::new()),
            max_idle_per_target,
            idle_ttl,
        }
    }

    /// Hands out a parked connection for `target`, discarding any that closed
    /// or outlived `idle_ttl`. `None` means the caller must dial.
    pub(super) fn take(&self, target: &str) -> Option<SendRequest<Full<Bytes>>> {
        let mut idle = self.idle.lock();
        let bucket = idle.get_mut(target)?;
        while let Some(conn) = bucket.pop() {
            if !conn.sender.is_closed() && conn.parked_at.elapsed() < self.idle_ttl {
                return Some(conn.sender);
            }
        }
        idle.remove(target);
        None
    }

    /// Parks `sender` for reuse. A connection that is already closed, or that
    /// would push the target past `max_idle_per_target`, is dropped instead —
    /// dropping the sender ends its driver task and closes the socket.
    pub(super) fn put(&self, target: &str, sender: SendRequest<Full<Bytes>>) {
        if self.max_idle_per_target == 0 || sender.is_closed() {
            return;
        }
        let mut idle = self.idle.lock();
        let bucket = idle.entry(target.to_owned()).or_default();
        bucket.retain(|conn| !conn.sender.is_closed() && conn.parked_at.elapsed() < self.idle_ttl);
        if bucket.len() >= self.max_idle_per_target {
            return;
        }
        bucket.push(IdleConn { sender, parked_at: Instant::now() });
    }
}

#[cfg(test)]
#[path = "tests/control_pool.rs"]
mod tests;
