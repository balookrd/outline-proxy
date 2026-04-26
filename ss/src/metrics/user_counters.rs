//! Per-user pre-resolved counter handles for the relay hot path.
//!
//! Resolving counters via `counter!(...)` in a tight loop pays a registry
//! lookup (label hashing + sharded HashMap probe) plus an extra `Arc::clone`
//! of the user-id label on every chunk.  At 65 KiB chunks and 10 Gbps that's
//! ~20K calls/s per connection.  This module caches the resolved
//! [`metrics::Counter`] handles per (user × protocol × direction) so the hot
//! loop only does the final virtual call into the storage atomic.

use std::sync::Arc;

use metrics::{Counter, counter, with_local_recorder};
use metrics_exporter_prometheus::PrometheusRecorder;

use super::labels::Protocol;

const VARIANTS: usize = Protocol::VARIANTS_COUNT;

pub struct PerUserCounters {
    tcp_payload_client_to_target: [Counter; VARIANTS],
    tcp_payload_target_to_client: [Counter; VARIANTS],
    udp_payload_target_to_client: [Counter; VARIANTS],
}

impl PerUserCounters {
    pub(super) fn new(recorder: &PrometheusRecorder, user_id: Arc<str>) -> Self {
        with_local_recorder(recorder, || Self {
            tcp_payload_client_to_target: build_payload_array(
                "outline_ss_tcp_payload_bytes_total",
                &user_id,
                "client_to_target",
            ),
            tcp_payload_target_to_client: build_payload_array(
                "outline_ss_tcp_payload_bytes_total",
                &user_id,
                "target_to_client",
            ),
            udp_payload_target_to_client: build_payload_array(
                "outline_ss_udp_payload_bytes_total",
                &user_id,
                "target_to_client",
            ),
        })
    }

    #[inline]
    pub fn tcp_in(&self, protocol: Protocol) -> &Counter {
        &self.tcp_payload_client_to_target[protocol.as_index()]
    }

    #[inline]
    pub fn tcp_out(&self, protocol: Protocol) -> &Counter {
        &self.tcp_payload_target_to_client[protocol.as_index()]
    }

    #[inline]
    pub fn udp_out(&self, protocol: Protocol) -> &Counter {
        &self.udp_payload_target_to_client[protocol.as_index()]
    }
}

fn build_payload_array(
    name: &'static str,
    user_id: &Arc<str>,
    direction: &'static str,
) -> [Counter; VARIANTS] {
    std::array::from_fn(|i| {
        let protocol = Protocol::from_index(i);
        counter!(
            name,
            "user"      => Arc::clone(user_id),
            "protocol"  => protocol.as_str(),
            "direction" => direction,
        )
    })
}
