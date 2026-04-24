use std::{sync::Arc, time::Instant};

use metrics::with_local_recorder;
use metrics::{counter, gauge, histogram};

use super::{DisconnectReason, Metrics, Protocol, Transport};

pub struct WebSocketSessionGuard {
    pub(super) metrics: Arc<Metrics>,
    pub(super) transport: Transport,
    pub(super) protocol: Protocol,
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
        with_local_recorder(&self.metrics.recorder, || {
            gauge!(
                "outline_ss_active_websocket_sessions",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str()
            )
            .decrement(1.0);
            counter!(
                "outline_ss_websocket_disconnects_total",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str(),
                "reason"    => reason.as_str()
            )
            .increment(1);
            histogram!(
                "outline_ss_websocket_session_duration_seconds",
                "transport" => transport.as_str(),
                "protocol"  => protocol.as_str()
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
        with_local_recorder(&self.metrics.recorder, || {
            gauge!(
                "outline_ss_active_tcp_upstream_connections",
                "user"     => user,
                "protocol" => protocol.as_str()
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
