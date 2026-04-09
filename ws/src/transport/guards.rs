use std::sync::Arc;
use tokio::task::JoinHandle;

use crate::metrics::{
    add_transport_connects_active, add_upstream_transports_active, record_transport_connect,
    record_upstream_transport,
};

pub(crate) struct AbortOnDrop(pub(crate) JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct TransportConnectGuard {
    source: &'static str,
    mode: &'static str,
    finished: bool,
}

impl TransportConnectGuard {
    pub(crate) fn new(source: &'static str, mode: &'static str) -> Self {
        add_transport_connects_active(source, mode, 1);
        record_transport_connect(source, mode, "started");
        Self {
            source,
            mode,
            finished: false,
        }
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

pub(crate) struct UpstreamTransportGuard {
    source: &'static str,
    protocol: &'static str,
}

impl UpstreamTransportGuard {
    pub(crate) fn new(source: &'static str, protocol: &'static str) -> Arc<Self> {
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
