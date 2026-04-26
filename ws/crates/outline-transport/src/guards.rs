use std::sync::Arc;
use tokio::task::JoinHandle;

use outline_metrics::{
    add_transport_connects_active, add_upstream_transports_active, record_transport_connect,
    record_upstream_transport,
};

/// `JoinHandle` newtype that aborts the task on `Drop`.
///
/// Tokio's bare `JoinHandle` only detaches the task on drop — it keeps
/// running. For tasks whose lifetime should be bounded by the owning
/// struct (UDP relay readers, NAT entry pumps, per-connection reader
/// loops) that detachment is a leak vector: any early `?`-return or
/// panic in the parent silently orphans the task, and the task then
/// keeps holding sockets, buffers and `Arc`-shared state for as long as
/// it can find anything to await on (UDP `recv` waits forever).
///
/// Stash one of these in a struct field and the field's natural drop
/// runs `abort()` on every exit path — no manual cleanup needed.
pub struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl AbortOnDrop {
    pub fn new(handle: JoinHandle<()>) -> Self {
        Self(handle)
    }
}

pub(crate) struct TransportConnectGuard {
    source: &'static str,
    mode: &'static str,
    finished: bool,
}

impl TransportConnectGuard {
    pub fn new(source: &'static str, mode: &'static str) -> Self {
        add_transport_connects_active(source, mode, 1);
        record_transport_connect(source, mode, "started");
        Self { source, mode, finished: false }
    }

    pub(crate) fn finish(&mut self, result: &'static str) {
        if !self.finished {
            self.finished = true;
            record_transport_connect(self.source, self.mode, result);
        }
    }
}

impl Drop for TransportConnectGuard {
    fn drop(&mut self) {
        if !self.finished {
            record_transport_connect(self.source, self.mode, "error");
        }
        add_transport_connects_active(self.source, self.mode, -1);
    }
}

pub struct UpstreamTransportGuard {
    source: &'static str,
    protocol: &'static str,
}

impl UpstreamTransportGuard {
    pub fn new(source: &'static str, protocol: &'static str) -> Arc<Self> {
        add_upstream_transports_active(source, protocol, 1);
        record_upstream_transport(source, protocol, "opened");
        Arc::new(Self { source, protocol })
    }
}

impl Drop for UpstreamTransportGuard {
    fn drop(&mut self) {
        record_upstream_transport(self.source, self.protocol, "closed");
        add_upstream_transports_active(self.source, self.protocol, -1);
    }
}
