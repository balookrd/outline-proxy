//! Per-user pre-resolved counter handles for the relay hot path.
//!
//! Resolving counters via `counter!(...)` in a tight loop pays a registry
//! lookup (label hashing + sharded HashMap probe) plus an extra `Arc::clone`
//! of the user-id label on every chunk.  At 65 KiB chunks and 10 Gbps that's
//! ~20K calls/s per connection.  This module caches the resolved
//! [`metrics::Counter`] handles per (user × app_protocol × protocol × direction)
//! so the hot loop only does the final virtual call into the storage atomic.

use std::sync::Arc;

use metrics::{Counter, counter, with_local_recorder};
use metrics_exporter_prometheus::PrometheusRecorder;

use super::labels::{AppProtocol, Protocol};

const PROTOCOL_VARIANTS: usize = Protocol::VARIANTS_COUNT;
const APP_PROTOCOL_VARIANTS: usize = AppProtocol::VARIANTS_COUNT;

/// 2D Counter array indexed by `[app_protocol_index][protocol_index]`.
/// Splitting the metric by `app_protocol` raises cardinality from
/// `users × 5 protocols × 2 directions` to `users × 2 app_protocols ×
/// 5 protocols × 2 directions`, but each row is still O(1) on the
/// hot path: one indexed lookup into a fixed-size array.
type CounterMatrix = [[Counter; PROTOCOL_VARIANTS]; APP_PROTOCOL_VARIANTS];

pub struct PerUserCounters {
    tcp_payload_client_to_target: CounterMatrix,
    tcp_payload_target_to_client: CounterMatrix,
    udp_payload_client_to_target: CounterMatrix,
    udp_payload_target_to_client: CounterMatrix,
}

impl PerUserCounters {
    pub(super) fn new(recorder: &PrometheusRecorder, user_id: Arc<str>) -> Self {
        with_local_recorder(recorder, || Self {
            tcp_payload_client_to_target: build_payload_matrix(
                "outline_ss_tcp_payload_bytes_total",
                &user_id,
                "client_to_target",
            ),
            tcp_payload_target_to_client: build_payload_matrix(
                "outline_ss_tcp_payload_bytes_total",
                &user_id,
                "target_to_client",
            ),
            udp_payload_client_to_target: build_payload_matrix(
                "outline_ss_udp_payload_bytes_total",
                &user_id,
                "client_to_target",
            ),
            udp_payload_target_to_client: build_payload_matrix(
                "outline_ss_udp_payload_bytes_total",
                &user_id,
                "target_to_client",
            ),
        })
    }

    #[inline]
    pub fn tcp_in(&self, app_protocol: AppProtocol, protocol: Protocol) -> &Counter {
        &self.tcp_payload_client_to_target[app_protocol.as_index()][protocol.as_index()]
    }

    #[inline]
    pub fn tcp_out(&self, app_protocol: AppProtocol, protocol: Protocol) -> &Counter {
        &self.tcp_payload_target_to_client[app_protocol.as_index()][protocol.as_index()]
    }

    #[inline]
    pub fn udp_in(&self, app_protocol: AppProtocol, protocol: Protocol) -> &Counter {
        &self.udp_payload_client_to_target[app_protocol.as_index()][protocol.as_index()]
    }

    #[inline]
    pub fn udp_out(&self, app_protocol: AppProtocol, protocol: Protocol) -> &Counter {
        &self.udp_payload_target_to_client[app_protocol.as_index()][protocol.as_index()]
    }
}

fn build_payload_matrix(
    name: &'static str,
    user_id: &Arc<str>,
    direction: &'static str,
) -> CounterMatrix {
    std::array::from_fn(|app_idx| {
        let app_protocol = AppProtocol::from_index(app_idx);
        std::array::from_fn(|p_idx| {
            let protocol = Protocol::from_index(p_idx);
            counter!(
                name,
                "user"         => Arc::clone(user_id),
                "app_protocol" => app_protocol.as_str(),
                "protocol"     => protocol.as_str(),
                "direction"    => direction,
            )
        })
    })
}
