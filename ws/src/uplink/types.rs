use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{Mutex, Notify, RwLock, Semaphore};
use tokio::time::Instant;

use crate::config::{LoadBalancingConfig, ProbeConfig, UplinkConfig};
use crate::transport::AnyWsStream;
use crate::types::TargetAddr;

#[derive(Clone, Debug)]
pub(super) struct UplinkStatus {
    pub(super) tcp_healthy: Option<bool>,
    pub(super) udp_healthy: Option<bool>,
    pub(super) tcp_latency: Option<Duration>,
    pub(super) udp_latency: Option<Duration>,
    pub(super) tcp_rtt_ewma: Option<Duration>,
    pub(super) udp_rtt_ewma: Option<Duration>,
    pub(super) tcp_penalty: PenaltyState,
    pub(super) udp_penalty: PenaltyState,
    pub(super) last_error: Option<String>,
    pub(super) last_checked: Option<Instant>,
    pub(super) cooldown_until_tcp: Option<Instant>,
    pub(super) cooldown_until_udp: Option<Instant>,
    pub(super) tcp_consecutive_failures: u32,
    pub(super) udp_consecutive_failures: u32,
    pub(super) tcp_consecutive_successes: u32,
    pub(super) udp_consecutive_successes: u32,
    /// When set, H3 connections for TCP encountered repeated APPLICATION_CLOSE
    /// errors at runtime (e.g. H3_INTERNAL_ERROR from server). Until this
    /// instant, the uplink falls back to H2 for TCP to avoid the storm.
    pub(super) h3_tcp_downgrade_until: Option<Instant>,
    /// Timestamp of the most recent real TCP data transfer through this uplink.
    /// Used to suppress probe cycles when the uplink is actively carrying traffic.
    pub(super) last_active_tcp: Option<Instant>,
    /// Timestamp of the most recent real UDP data transfer through this uplink.
    pub(super) last_active_udp: Option<Instant>,
    /// Timestamp of the most recent early probe wakeup caused by a runtime
    /// failure. Used to keep runtime-failure storms from waking the probe loop
    /// on every fresh cooldown window under sustained load.
    pub(super) last_probe_wakeup_tcp: Option<Instant>,
    pub(super) last_probe_wakeup_udp: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PenaltyState {
    pub(super) value_secs: f64,
    pub(super) updated_at: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(super) struct StickyRoute {
    pub(super) uplink_index: usize,
    pub(super) expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct UplinkCandidate {
    pub index: usize,
    pub uplink: Arc<UplinkConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum RoutingKey {
    Global,
    TransportGlobal(TransportKind),
    Target {
        transport: TransportKind,
        target: TargetAddr,
    },
    Default(TransportKind),
}

impl fmt::Display for RoutingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::TransportGlobal(transport) => {
                write!(
                    f,
                    "{}:global",
                    super::scoring::transport_key_prefix(*transport)
                )
            }
            Self::Target { transport, target } => {
                write!(
                    f,
                    "{}:{target}",
                    super::scoring::transport_key_prefix(*transport)
                )
            }
            Self::Default(transport) => write!(
                f,
                "{}:default",
                super::scoring::transport_key_prefix(*transport)
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UplinkManagerSnapshot {
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

impl Default for UplinkStatus {
    fn default() -> Self {
        Self {
            tcp_healthy: None,
            udp_healthy: None,
            tcp_latency: None,
            udp_latency: None,
            tcp_rtt_ewma: None,
            udp_rtt_ewma: None,
            tcp_penalty: PenaltyState::default(),
            udp_penalty: PenaltyState::default(),
            last_error: None,
            last_checked: None,
            cooldown_until_tcp: None,
            cooldown_until_udp: None,
            tcp_consecutive_failures: 0,
            udp_consecutive_failures: 0,
            tcp_consecutive_successes: 0,
            udp_consecutive_successes: 0,
            h3_tcp_downgrade_until: None,
            last_active_tcp: None,
            last_active_udp: None,
            last_probe_wakeup_tcp: None,
            last_probe_wakeup_udp: None,
        }
    }
}

pub(crate) struct UplinkManagerInner {
    pub(super) uplinks: Vec<Arc<UplinkConfig>>,
    pub(super) probe: ProbeConfig,
    pub(super) load_balancing: LoadBalancingConfig,
    pub(super) statuses: RwLock<Vec<UplinkStatus>>,
    pub(super) global_active_uplink: RwLock<Option<usize>>,
    pub(super) tcp_active_uplink: RwLock<Option<usize>>,
    pub(super) udp_active_uplink: RwLock<Option<usize>>,
    pub(super) sticky_routes: RwLock<HashMap<RoutingKey, StickyRoute>>,
    pub(super) standby_pools: Vec<StandbyPool>,
    pub(super) probe_execution_limit: Arc<Semaphore>,
    pub(super) probe_dial_limit: Arc<Semaphore>,
    /// Notified when a runtime failure sets a fresh cooldown, so the probe
    /// loop wakes up immediately instead of waiting for the next interval.
    pub(super) probe_wakeup: Arc<Notify>,
}

pub(super) struct StandbyPool {
    pub(super) tcp: Mutex<VecDeque<AnyWsStream>>,
    pub(super) udp: Mutex<VecDeque<AnyWsStream>>,
    pub(super) tcp_refill: Mutex<()>,
    pub(super) udp_refill: Mutex<()>,
}

impl StandbyPool {
    pub(super) fn new() -> Self {
        Self {
            tcp: Mutex::new(VecDeque::new()),
            udp: Mutex::new(VecDeque::new()),
            tcp_refill: Mutex::new(()),
            udp_refill: Mutex::new(()),
        }
    }
}

#[derive(Debug)]
pub(super) struct ProbeOutcome {
    pub(super) tcp_ok: bool,
    /// false when the uplink has no `udp_ws_url` — means "UDP not applicable",
    /// not "UDP probe failed".  Health and standby tracking are skipped in
    /// this case so that Grafana shows empty (unknown) rather than red (0).
    pub(super) udp_ok: bool,
    pub(super) udp_applicable: bool,
    pub(super) tcp_latency: Option<Duration>,
    pub(super) udp_latency: Option<Duration>,
}

#[derive(Clone)]
pub(super) struct CandidateState {
    pub(super) index: usize,
    pub(super) uplink: Arc<UplinkConfig>,
    pub(super) healthy: bool,
    pub(super) score: Option<Duration>,
}
