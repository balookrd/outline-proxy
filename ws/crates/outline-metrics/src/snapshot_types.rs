//! Plain-data snapshot types that cross the boundary between the main
//! binary (producer of probe / uplink / process state) and the metrics
//! rendering code in this crate (consumer).
//!
//! Kept outside any feature gate so the producers in the main binary can
//! build these values regardless of whether the `prometheus` feature is
//! enabled — they just happen to be handed to a no-op renderer in that
//! case.

use serde::Serialize;

// ── Uplink snapshots ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct UplinkManagerSnapshot {
    /// Group this snapshot was generated for. Surfaced as the `group`
    /// Prometheus label on snapshot-rendered metrics.
    pub group: String,
    pub generated_at_unix_ms: u128,
    pub load_balancing_mode: String,
    pub routing_scope: String,
    pub global_active_uplink: Option<String>,
    /// Active uplink for TCP in per_uplink routing scope.
    pub tcp_active_uplink: Option<String>,
    /// Active uplink for UDP in per_uplink routing scope.
    pub udp_active_uplink: Option<String>,
    pub uplinks: Vec<UplinkSnapshot>,
    pub sticky_routes: Vec<StickyRouteSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UplinkSnapshot {
    pub index: usize,
    pub name: String,
    /// Name of the uplink group this entry belongs to. Emitted as the
    /// `group` Prometheus label alongside `uplink`.
    pub group: String,
    pub weight: f64,
    pub tcp_healthy: Option<bool>,
    pub udp_healthy: Option<bool>,
    pub tcp_latency_ms: Option<u128>,
    pub udp_latency_ms: Option<u128>,
    pub tcp_rtt_ewma_ms: Option<u128>,
    pub udp_rtt_ewma_ms: Option<u128>,
    pub tcp_penalty_ms: Option<u128>,
    pub udp_penalty_ms: Option<u128>,
    pub tcp_effective_latency_ms: Option<u128>,
    pub udp_effective_latency_ms: Option<u128>,
    pub tcp_score_ms: Option<u128>,
    pub udp_score_ms: Option<u128>,
    pub cooldown_tcp_ms: Option<u128>,
    pub cooldown_udp_ms: Option<u128>,
    pub last_checked_ago_ms: Option<u128>,
    pub last_error: Option<String>,
    pub standby_tcp_ready: usize,
    pub standby_udp_ready: usize,
    pub tcp_consecutive_failures: u32,
    pub udp_consecutive_failures: u32,
    pub h3_tcp_downgrade_until_ms: Option<u128>,
    pub h3_udp_downgrade_until_ms: Option<u128>,
    pub last_active_tcp_ago_ms: Option<u128>,
    pub last_active_udp_ago_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StickyRouteSnapshot {
    pub key: String,
    pub uplink_index: usize,
    pub uplink_name: String,
    pub expires_in_ms: u128,
}

// ── Process-memory snapshots ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProcessMemorySnapshot {
    pub rss_bytes: Option<u64>,
    pub virtual_bytes: Option<u64>,
    pub heap_bytes: Option<u64>,
    pub heap_allocated_bytes: Option<u64>,
    pub heap_free_bytes: Option<u64>,
    pub heap_mode: &'static str,
    pub open_fds: Option<u64>,
    pub thread_count: Option<u64>,
    pub fd_snapshot: Option<ProcessFdSnapshot>,
}

impl Default for ProcessMemorySnapshot {
    fn default() -> Self {
        Self {
            rss_bytes: None,
            virtual_bytes: None,
            heap_bytes: None,
            heap_allocated_bytes: None,
            heap_free_bytes: None,
            heap_mode: "unavailable",
            open_fds: None,
            thread_count: None,
            fd_snapshot: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessFdSnapshot {
    pub total: u64,
    pub sockets: u64,
    pub pipes: u64,
    pub anon_inodes: u64,
    pub regular_files: u64,
    pub other: u64,
    /// Per-(protocol, family, state) counts of TCP/UDP sockets currently
    /// owned by this process. See the producer in the main binary for the
    /// precise Linux-specific sampling rules.
    pub socket_states: Option<Vec<SocketStateCount>>,
}

#[derive(Debug, Clone)]
pub struct SocketStateCount {
    pub protocol: &'static str,
    pub family: &'static str,
    pub state: &'static str,
    pub count: u64,
}
