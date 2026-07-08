//! Home-side registry mapping a relayed session id to its live carrier monitor,
//! so an edge `THROTTLE_HINT` control datagram can wake the right relay writer.
//!
//! The home cannot run local throttle detection on a relayed carrier: its own
//! send counters measure the home→mesh hop (fast cross-country QUIC), not the
//! edge→client last mile that actually throttles. So the *edge* detects a
//! stalled client segment and sends a `THROTTLE_HINT` datagram; the home looks
//! the session up here and pings the monitor's `signal()`, which the writer
//! turns into one client-facing OCTL cover frame (see `ws_writer`).
//!
//! Entries are weak: the registry never keeps a relay's monitor alive. The live
//! relay task holds the strong `Arc`; the registration is a RAII guard the relay
//! holds for its lifetime and drops on teardown, removing its own entry. The
//! `Weak` also guards a torn-down relay whose guard has not run yet —
//! `upgrade()` returns `None` and the hint is dropped.

use std::sync::{Arc, Weak};

use dashmap::DashMap;

use crate::server::transport::throughput_monitor::ThroughputMonitor;

/// Maps a relayed session id (16 bytes, the client's resume id) to its live
/// carrier monitor. A cloneable handle over a shared map.
#[derive(Clone, Default)]
pub(in crate::server) struct ThrottleRegistry {
    inner: Arc<DashMap<[u8; 16], Weak<ThroughputMonitor>>>,
}

impl ThrottleRegistry {
    pub(in crate::server) fn new() -> Self {
        Self::default()
    }

    /// Registers `monitor` under `session_id`, returning a RAII guard that
    /// removes the entry on drop. A concurrent re-registration for the same id
    /// (edge switch: the new relay registers before the old one's guard runs)
    /// overwrites the entry; the stale guard then removes it only if it is still
    /// its own (pointer identity), so a late drop never evicts the fresh entry.
    pub(in crate::server) fn register(
        &self,
        session_id: [u8; 16],
        monitor: &Arc<ThroughputMonitor>,
    ) -> ThrottleRegistration {
        let weak = Arc::downgrade(monitor);
        self.inner.insert(session_id, weak.clone());
        ThrottleRegistration {
            inner: Arc::clone(&self.inner),
            session_id,
            weak,
        }
    }

    /// Routes a `THROTTLE_HINT` to the registered monitor: wakes its writer to
    /// inject one OCTL cover frame. Best-effort — returns `false` when no live
    /// monitor is registered for `session_id` (unknown or torn-down session), so
    /// the caller can drop the hint silently.
    pub(in crate::server) fn route_hint(&self, session_id: &[u8; 16]) -> bool {
        // Clone the weak and release the shard lock before touching the monitor.
        let Some(weak) = self.inner.get(session_id).map(|e| e.clone()) else {
            return false;
        };
        let Some(monitor) = weak.upgrade() else {
            return false;
        };
        monitor.signal().notify_one();
        true
    }

    #[cfg(test)]
    pub(in crate::server) fn len(&self) -> usize {
        self.inner.len()
    }
}

/// RAII registration handle: the relay holds it for its lifetime; dropping it
/// unregisters the session, but only if the entry is still this registration's.
pub(in crate::server) struct ThrottleRegistration {
    inner: Arc<DashMap<[u8; 16], Weak<ThroughputMonitor>>>,
    session_id: [u8; 16],
    weak: Weak<ThroughputMonitor>,
}

impl Drop for ThrottleRegistration {
    fn drop(&mut self) {
        // Evict only if the current entry is still ours: a re-registration for
        // the same session id (edge switch) must not be removed by this stale
        // guard.
        self.inner
            .remove_if(&self.session_id, |_, existing| existing.ptr_eq(&self.weak));
    }
}

#[cfg(test)]
#[path = "tests/throttle.rs"]
mod tests;
