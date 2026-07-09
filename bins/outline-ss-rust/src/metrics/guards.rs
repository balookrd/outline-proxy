use std::{sync::Arc, time::Instant};

use metrics::with_local_recorder;
use metrics::{counter, gauge, histogram};

use super::{AppProtocol, DisconnectReason, Metrics, Protocol, Transport};

pub struct WebSocketSessionGuard {
    pub(super) metrics: Arc<Metrics>,
    pub(super) transport: Transport,
    pub(super) protocol: Protocol,
    pub(super) app_protocol: AppProtocol,
    pub(super) started_at: Instant,
    pub(super) finished: bool,
}

impl WebSocketSessionGuard {
    pub fn finish(mut self, reason: DisconnectReason) {
        if !self.finished {
            self.close(reason);
        }
    }

    fn close(&mut self, reason: DisconnectReason) {
        self.finished = true;
        let duration = self.started_at.elapsed().as_secs_f64();
        let transport = self.transport;
        let protocol = self.protocol;
        let app_protocol = self.app_protocol;
        with_local_recorder(&self.metrics.recorder, || {
            gauge!(
                "outline_ss_active_websocket_sessions",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .decrement(1.0);
            counter!(
                "outline_ss_websocket_disconnects_total",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str(),
                "reason"       => reason.as_str()
            )
            .increment(1);
            histogram!(
                "outline_ss_websocket_session_duration_seconds",
                "transport"    => transport.as_str(),
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .record(duration);
        });
    }
}

impl Drop for WebSocketSessionGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.close(DisconnectReason::Error);
        }
    }
}

pub struct TcpUpstreamGuard {
    pub(super) metrics: Arc<Metrics>,
    pub(super) user_id: Arc<str>,
    pub(super) protocol: Protocol,
    pub(super) app_protocol: AppProtocol,
    pub(super) finished: bool,
}

impl TcpUpstreamGuard {
    pub fn finish(mut self) {
        if !self.finished {
            self.close();
        }
    }

    fn close(&mut self) {
        self.finished = true;
        let user = Arc::clone(&self.user_id);
        let protocol = self.protocol;
        let app_protocol = self.app_protocol;
        with_local_recorder(&self.metrics.recorder, || {
            gauge!(
                "outline_ss_active_tcp_upstream_connections",
                "user"         => user,
                "protocol"     => protocol.as_str(),
                "app_protocol" => app_protocol.as_str()
            )
            .decrement(1.0);
        });
    }
}

impl Drop for TcpUpstreamGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.close();
        }
    }
}

/// RAII guard for one in-flight home-side mesh relay. Increments
/// `outline_ss_mesh_relay_active` on creation and decrements it on drop, so the
/// gauge tracks how many relayed sessions this home node is serving over the
/// mesh right now. Held for the lifetime of `serve_relayed`, so it also covers
/// every early-exit and abort path without leaking the gauge.
pub struct MeshRelayGuard {
    metrics: Arc<Metrics>,
}

impl MeshRelayGuard {
    pub(super) fn new(metrics: Arc<Metrics>) -> Self {
        with_local_recorder(&metrics.recorder, || {
            gauge!("outline_ss_mesh_relay_active").increment(1.0);
        });
        Self { metrics }
    }
}

impl Drop for MeshRelayGuard {
    fn drop(&mut self) {
        with_local_recorder(&self.metrics.recorder, || {
            gauge!("outline_ss_mesh_relay_active").decrement(1.0);
        });
    }
}
