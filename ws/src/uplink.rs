use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{debug, info, warn};

use crate::config::{
    DnsProbeConfig, HttpProbeConfig, LoadBalancingConfig, ProbeConfig, UplinkConfig,
};
use crate::memory::{maybe_shrink_hash_map, maybe_shrink_vecdeque};
use crate::metrics;
use crate::transport::{
    AnyWsStream, TcpShadowsocksReader, TcpShadowsocksWriter, UdpWsTransport, connect_websocket,
};
use crate::types::TargetAddr;

const WARM_STANDBY_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct UplinkManager {
    inner: Arc<UplinkManagerInner>,
}

struct UplinkManagerInner {
    uplinks: Vec<Arc<UplinkConfig>>,
    probe: ProbeConfig,
    load_balancing: LoadBalancingConfig,
    statuses: RwLock<Vec<UplinkStatus>>,
    sticky_routes: RwLock<HashMap<RoutingKey, StickyRoute>>,
    standby_pools: Vec<StandbyPool>,
    probe_execution_limit: Arc<Semaphore>,
    probe_dial_limit: Arc<Semaphore>,
}

#[derive(Clone, Debug)]
struct UplinkStatus {
    tcp_healthy: Option<bool>,
    udp_healthy: Option<bool>,
    tcp_latency: Option<Duration>,
    udp_latency: Option<Duration>,
    tcp_rtt_ewma: Option<Duration>,
    udp_rtt_ewma: Option<Duration>,
    tcp_penalty: PenaltyState,
    udp_penalty: PenaltyState,
    last_error: Option<String>,
    last_checked: Option<Instant>,
    cooldown_until_tcp: Option<Instant>,
    cooldown_until_udp: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Default)]
struct PenaltyState {
    value_secs: f64,
    updated_at: Option<Instant>,
}

#[derive(Clone, Debug)]
struct StickyRoute {
    uplink_index: usize,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct UplinkCandidate {
    pub index: usize,
    pub uplink: Arc<UplinkConfig>,
}

#[derive(Clone, Copy, Debug)]
pub enum TransportKind {
    Tcp,
    Udp,
}

type RoutingKey = String;

#[derive(Debug, Clone, Serialize)]
pub struct UplinkManagerSnapshot {
    pub generated_at_unix_ms: u128,
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
        }
    }
}

impl StandbyPool {
    fn new() -> Self {
        Self {
            tcp: Mutex::new(VecDeque::new()),
            udp: Mutex::new(VecDeque::new()),
            tcp_refill: Mutex::new(()),
            udp_refill: Mutex::new(()),
        }
    }
}

impl UplinkManager {
    pub fn new(
        uplinks: Vec<UplinkConfig>,
        probe: ProbeConfig,
        load_balancing: LoadBalancingConfig,
    ) -> Result<Self> {
        if uplinks.is_empty() {
            bail!("at least one uplink must be configured");
        }

        let count = uplinks.len();
        let probe_max_concurrent = probe.max_concurrent;
        let probe_max_dials = probe.max_dials;
        Ok(Self {
            inner: Arc::new(UplinkManagerInner {
                uplinks: uplinks.into_iter().map(Arc::new).collect(),
                probe,
                load_balancing,
                statuses: RwLock::new(vec![UplinkStatus::default(); count]),
                sticky_routes: RwLock::new(HashMap::new()),
                standby_pools: (0..count).map(|_| StandbyPool::new()).collect(),
                probe_execution_limit: Arc::new(Semaphore::new(probe_max_concurrent)),
                probe_dial_limit: Arc::new(Semaphore::new(probe_max_dials)),
            }),
        })
    }

    pub fn spawn_probe_loop(&self) {
        if !self.inner.probe.enabled() {
            return;
        }

        let manager = self.clone();
        tokio::spawn(async move {
            manager.probe_all().await;
            loop {
                sleep(manager.inner.probe.interval).await;
                manager.probe_all().await;
            }
        });
    }

    pub fn spawn_warm_standby_loop(&self) {
        if self.inner.load_balancing.warm_standby_tcp == 0
            && self.inner.load_balancing.warm_standby_udp == 0
        {
            return;
        }

        let manager = self.clone();
        tokio::spawn(async move {
            manager.refill_all_standby().await;
            loop {
                sleep(WARM_STANDBY_MAINTENANCE_INTERVAL).await;
                manager.refill_all_standby().await;
            }
        });
    }

    pub async fn run_standby_maintenance(&self) {
        self.refill_all_standby().await;
    }

    pub fn uplinks(&self) -> &[Arc<UplinkConfig>] {
        &self.inner.uplinks
    }

    pub async fn snapshot(&self) -> UplinkManagerSnapshot {
        let now = Instant::now();
        let statuses = self.inner.statuses.read().await.clone();
        let sticky = self.inner.sticky_routes.read().await.clone();

        let mut uplinks = Vec::with_capacity(self.inner.uplinks.len());
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            let status = &statuses[index];
            let standby_tcp_ready = self.inner.standby_pools[index].tcp.lock().await.len();
            let standby_udp_ready = self.inner.standby_pools[index].udp.lock().await.len();
            let tcp_penalty = current_penalty(&status.tcp_penalty, now, &self.inner.load_balancing);
            let udp_penalty = current_penalty(&status.udp_penalty, now, &self.inner.load_balancing);
            let tcp_effective_latency =
                effective_latency(status, TransportKind::Tcp, now, &self.inner.load_balancing);
            let udp_effective_latency =
                effective_latency(status, TransportKind::Udp, now, &self.inner.load_balancing);
            let tcp_score = score_latency(
                status,
                uplink.weight,
                TransportKind::Tcp,
                now,
                &self.inner.load_balancing,
            );
            let udp_score = score_latency(
                status,
                uplink.weight,
                TransportKind::Udp,
                now,
                &self.inner.load_balancing,
            );
            uplinks.push(UplinkSnapshot {
                index,
                name: uplink.name.clone(),
                weight: uplink.weight,
                tcp_healthy: status.tcp_healthy,
                udp_healthy: status.udp_healthy,
                tcp_latency_ms: status.tcp_latency.map(|v| v.as_millis()),
                udp_latency_ms: status.udp_latency.map(|v| v.as_millis()),
                tcp_rtt_ewma_ms: status.tcp_rtt_ewma.map(|v| v.as_millis()),
                udp_rtt_ewma_ms: status.udp_rtt_ewma.map(|v| v.as_millis()),
                tcp_penalty_ms: duration_to_millis_option(tcp_penalty),
                udp_penalty_ms: duration_to_millis_option(udp_penalty),
                tcp_effective_latency_ms: duration_to_millis_option(tcp_effective_latency),
                udp_effective_latency_ms: duration_to_millis_option(udp_effective_latency),
                tcp_score_ms: duration_to_millis_option(tcp_score),
                udp_score_ms: duration_to_millis_option(udp_score),
                cooldown_tcp_ms: status
                    .cooldown_until_tcp
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                cooldown_udp_ms: status
                    .cooldown_until_udp
                    .and_then(|until| until.checked_duration_since(now))
                    .map(|v| v.as_millis()),
                last_checked_ago_ms: status
                    .last_checked
                    .map(|checked| now.duration_since(checked).as_millis()),
                last_error: status.last_error.clone(),
                standby_tcp_ready,
                standby_udp_ready,
            });
        }

        let sticky_routes = sticky
            .into_iter()
            .filter_map(|(key, route)| {
                route
                    .expires_at
                    .checked_duration_since(now)
                    .map(|remaining| StickyRouteSnapshot {
                        key,
                        uplink_index: route.uplink_index,
                        uplink_name: self.inner.uplinks[route.uplink_index].name.clone(),
                        expires_in_ms: remaining.as_millis(),
                    })
            })
            .collect();

        UplinkManagerSnapshot {
            generated_at_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            uplinks,
            sticky_routes,
        }
    }

    pub async fn tcp_candidates(&self, target: &TargetAddr) -> Vec<UplinkCandidate> {
        self.ordered_candidates(TransportKind::Tcp, Some(target))
            .await
    }

    pub async fn udp_candidates(&self, target: Option<&TargetAddr>) -> Vec<UplinkCandidate> {
        self.ordered_candidates(TransportKind::Udp, target).await
    }

    pub async fn report_runtime_failure(
        &self,
        index: usize,
        transport: TransportKind,
        error: &anyhow::Error,
    ) {
        {
            let mut statuses = self.inner.statuses.write().await;
            let now = Instant::now();
            let status = &mut statuses[index];
            status.last_error = Some(format!("{error:#}"));
            let uplink_name = self.inner.uplinks[index].name.as_str();
            match transport {
                TransportKind::Tcp => {
                    add_penalty(&mut status.tcp_penalty, now, &self.inner.load_balancing);
                    status.tcp_healthy = Some(false);
                    status.cooldown_until_tcp =
                        Some(now + self.inner.load_balancing.failure_cooldown);
                    metrics::record_runtime_failure("tcp", uplink_name);
                }
                TransportKind::Udp => {
                    add_penalty(&mut status.udp_penalty, now, &self.inner.load_balancing);
                    status.udp_healthy = Some(false);
                    status.cooldown_until_udp =
                        Some(now + self.inner.load_balancing.failure_cooldown);
                    metrics::record_runtime_failure("udp", uplink_name);
                }
            }
        }
        self.clear_standby(index, transport).await;
    }

    pub async fn acquire_tcp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
    ) -> Result<AnyWsStream> {
        let pool = &self.inner.standby_pools[candidate.index];
        if let Some(ws) = pool.tcp.lock().await.pop_front() {
            self.spawn_refill(candidate.index, TransportKind::Tcp);
            metrics::record_warm_standby_acquire("tcp", &candidate.uplink.name, "hit");
            debug!(uplink = %candidate.uplink.name, "using warm-standby TCP websocket");
            return Ok(ws);
        }

        metrics::record_warm_standby_acquire("tcp", &candidate.uplink.name, "miss");
        debug!(uplink = %candidate.uplink.name, "no warm-standby TCP websocket available, dialing on-demand");
        connect_websocket(
            &candidate.uplink.tcp_ws_url,
            candidate.uplink.tcp_ws_mode,
            candidate.uplink.fwmark,
        )
        .await
        .with_context(|| format!("failed to connect to {}", candidate.uplink.tcp_ws_url))
    }

    pub async fn acquire_udp_standby_or_connect(
        &self,
        candidate: &UplinkCandidate,
    ) -> Result<UdpWsTransport> {
        let pool = &self.inner.standby_pools[candidate.index];
        if let Some(ws) = pool.udp.lock().await.pop_front() {
            self.spawn_refill(candidate.index, TransportKind::Udp);
            metrics::record_warm_standby_acquire("udp", &candidate.uplink.name, "hit");
            debug!(uplink = %candidate.uplink.name, "using warm-standby UDP websocket");
            return Ok(UdpWsTransport::from_websocket(
                ws,
                candidate.uplink.cipher,
                &candidate.uplink.password,
            ));
        }

        metrics::record_warm_standby_acquire("udp", &candidate.uplink.name, "miss");
        debug!(uplink = %candidate.uplink.name, "no warm-standby UDP websocket available, dialing on-demand");
        let udp_ws_url = candidate.uplink.udp_ws_url.as_ref().ok_or_else(|| {
            anyhow!(
                "udp_ws_url is not configured for uplink {}",
                candidate.uplink.name
            )
        })?;
        UdpWsTransport::connect(
            udp_ws_url,
            candidate.uplink.udp_ws_mode,
            candidate.uplink.cipher,
            &candidate.uplink.password,
            candidate.uplink.fwmark,
        )
        .await
        .with_context(|| format!("failed to connect to {}", udp_ws_url))
    }

    async fn ordered_candidates(
        &self,
        transport: TransportKind,
        target: Option<&TargetAddr>,
    ) -> Vec<UplinkCandidate> {
        self.prune_sticky_routes().await;
        let routing_key = routing_key(transport, target);
        let statuses = self.inner.statuses.read().await.clone();
        let now = Instant::now();

        let mut candidates = self
            .inner
            .uplinks
            .iter()
            .enumerate()
            .filter(|(_, uplink)| match transport {
                TransportKind::Tcp => true,
                TransportKind::Udp => uplink.udp_ws_url.is_some(),
            })
            .map(|(index, uplink)| CandidateState {
                index,
                uplink: Arc::clone(uplink),
                healthy: effective_health(&statuses[index], transport, now),
                score: score_latency(
                    &statuses[index],
                    uplink.weight,
                    transport,
                    now,
                    &self.inner.load_balancing,
                ),
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Vec::new();
        }

        candidates.sort_by(|left, right| {
            rightless_bool(left.healthy)
                .cmp(&rightless_bool(right.healthy))
                .reverse()
                .then_with(|| {
                    left.score
                        .unwrap_or(Duration::MAX)
                        .cmp(&right.score.unwrap_or(Duration::MAX))
                })
                .then_with(|| left.index.cmp(&right.index))
        });

        let preferred_index = self
            .preferred_sticky_index(&routing_key, &candidates, &statuses)
            .await;
        if let Some(index) = preferred_index {
            if let Some(pos) = candidates
                .iter()
                .position(|candidate| candidate.index == index)
            {
                let sticky = candidates.remove(pos);
                candidates.insert(0, sticky);
            }
        } else if let Some(first) = candidates.first() {
            self.store_sticky_route(routing_key, first.index).await;
        }

        candidates
            .into_iter()
            .map(|candidate| UplinkCandidate {
                index: candidate.index,
                uplink: candidate.uplink,
            })
            .collect()
    }

    async fn refill_all_standby(&self) {
        for index in 0..self.inner.uplinks.len() {
            self.maintain_pool(index, TransportKind::Tcp).await;
            self.maintain_pool(index, TransportKind::Udp).await;
        }
    }

    fn spawn_refill(&self, index: usize, transport: TransportKind) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.refill_pool(index, transport).await;
        });
    }

    async fn maintain_pool(&self, index: usize, transport: TransportKind) {
        self.validate_pool(index, transport).await;
        self.refill_pool(index, transport).await;
    }

    async fn refill_pool(&self, index: usize, transport: TransportKind) {
        let desired = match transport {
            TransportKind::Tcp => self.inner.load_balancing.warm_standby_tcp,
            TransportKind::Udp => self.inner.load_balancing.warm_standby_udp,
        };
        if desired == 0 {
            return;
        }

        let uplink = Arc::clone(&self.inner.uplinks[index]);
        let pool = &self.inner.standby_pools[index];
        let refill_guard = match transport {
            TransportKind::Tcp => pool.tcp_refill.lock().await,
            TransportKind::Udp => pool.udp_refill.lock().await,
        };

        loop {
            let len = match transport {
                TransportKind::Tcp => pool.tcp.lock().await.len(),
                TransportKind::Udp => pool.udp.lock().await.len(),
            };
            if len >= desired {
                break;
            }

            let ws = match transport {
                TransportKind::Tcp => {
                    connect_websocket(&uplink.tcp_ws_url, uplink.tcp_ws_mode, uplink.fwmark)
                        .await
                        .with_context(|| format!("failed to preconnect to {}", uplink.tcp_ws_url))
                }
                TransportKind::Udp => {
                    let Some(url) = uplink.udp_ws_url.as_ref() else {
                        break;
                    };
                    connect_websocket(url, uplink.udp_ws_mode, uplink.fwmark)
                        .await
                        .with_context(|| format!("failed to preconnect to {}", url))
                }
            };

            match ws {
                Ok(ws) => {
                    let pool_vec = match transport {
                        TransportKind::Tcp => &pool.tcp,
                        TransportKind::Udp => &pool.udp,
                    };
                    pool_vec.lock().await.push_back(ws);
                    metrics::record_warm_standby_refill(
                        match transport {
                            TransportKind::Tcp => "tcp",
                            TransportKind::Udp => "udp",
                        },
                        &uplink.name,
                        true,
                    );
                    debug!(
                        uplink = %uplink.name,
                        transport = ?transport,
                        desired,
                        "warm-standby websocket replenished"
                    );
                }
                Err(error) => {
                    metrics::record_warm_standby_refill(
                        match transport {
                            TransportKind::Tcp => "tcp",
                            TransportKind::Udp => "udp",
                        },
                        &uplink.name,
                        false,
                    );
                    warn!(
                        uplink = %uplink.name,
                        transport = ?transport,
                        error = %format!("{error:#}"),
                        "failed to replenish warm-standby websocket"
                    );
                    break;
                }
            }
        }

        drop(refill_guard);
    }

    async fn validate_pool(&self, index: usize, transport: TransportKind) {
        let desired = match transport {
            TransportKind::Tcp => self.inner.load_balancing.warm_standby_tcp,
            TransportKind::Udp => self.inner.load_balancing.warm_standby_udp,
        };
        if desired == 0 {
            return;
        }

        let uplink = Arc::clone(&self.inner.uplinks[index]);
        let pool = &self.inner.standby_pools[index];
        let mut drained = VecDeque::new();
        {
            let mut guard = match transport {
                TransportKind::Tcp => pool.tcp.lock().await,
                TransportKind::Udp => pool.udp.lock().await,
            };
            drained.extend(guard.drain(..));
        }

        if drained.is_empty() {
            return;
        }

        let mut alive = VecDeque::with_capacity(drained.len());
        while let Some(mut ws) = drained.pop_front() {
            let started = Instant::now();
            let result = ping_idle_websocket(&mut ws).await;
            metrics::record_probe(
                &uplink.name,
                match transport {
                    TransportKind::Tcp => "tcp",
                    TransportKind::Udp => "udp",
                },
                "standby_ws",
                result.is_ok(),
                started.elapsed(),
            );
            match result {
                Ok(()) => alive.push_back(ws),
                Err(error) => {
                    if is_expected_standby_probe_failure(&error) {
                        debug!(
                            uplink = %uplink.name,
                            transport = ?transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket"
                        );
                    } else {
                        warn!(
                            uplink = %uplink.name,
                            transport = ?transport,
                            error = %format!("{error:#}"),
                            "dropping stale warm-standby websocket"
                        );
                    }
                }
            }
        }

        let mut guard = match transport {
            TransportKind::Tcp => pool.tcp.lock().await,
            TransportKind::Udp => pool.udp.lock().await,
        };
        guard.extend(alive);
        maybe_shrink_vecdeque(&mut guard);
    }

    async fn clear_standby(&self, index: usize, transport: TransportKind) {
        let pool = &self.inner.standby_pools[index];
        match transport {
            TransportKind::Tcp => {
                let mut guard = pool.tcp.lock().await;
                guard.clear();
                maybe_shrink_vecdeque(&mut guard);
            }
            TransportKind::Udp => {
                let mut guard = pool.udp.lock().await;
                guard.clear();
                maybe_shrink_vecdeque(&mut guard);
            }
        }
    }

    async fn preferred_sticky_index(
        &self,
        routing_key: &str,
        candidates: &[CandidateState],
        statuses: &[UplinkStatus],
    ) -> Option<usize> {
        let sticky_index = {
            let sticky = self.inner.sticky_routes.read().await;
            sticky.get(routing_key).map(|route| route.uplink_index)
        }?;

        let sticky = candidates
            .iter()
            .find(|candidate| candidate.index == sticky_index)?;
        if !sticky.healthy {
            self.store_sticky_route(routing_key.to_string(), candidates[0].index)
                .await;
            return Some(candidates[0].index);
        }

        let fastest = candidates
            .iter()
            .find(|candidate| candidate.healthy)
            .unwrap_or(sticky);
        let transport = transport_from_key(routing_key);
        let now = Instant::now();
        let sticky_score = score_latency(
            &statuses[sticky.index],
            self.inner.uplinks[sticky.index].weight,
            transport,
            now,
            &self.inner.load_balancing,
        );
        let fastest_score = score_latency(
            &statuses[fastest.index],
            self.inner.uplinks[fastest.index].weight,
            transport,
            now,
            &self.inner.load_balancing,
        );

        let should_switch = match (sticky_score, fastest_score) {
            (Some(sticky_score), Some(fastest_score)) => {
                sticky.index != fastest.index
                    && sticky_score > fastest_score + self.inner.load_balancing.hysteresis
            }
            _ => false,
        };

        if should_switch {
            self.store_sticky_route(routing_key.to_string(), fastest.index)
                .await;
            Some(fastest.index)
        } else {
            self.store_sticky_route(routing_key.to_string(), sticky.index)
                .await;
            Some(sticky.index)
        }
    }

    async fn store_sticky_route(&self, routing_key: RoutingKey, uplink_index: usize) {
        let mut sticky = self.inner.sticky_routes.write().await;
        sticky.insert(
            routing_key,
            StickyRoute {
                uplink_index,
                expires_at: Instant::now() + self.inner.load_balancing.sticky_ttl,
            },
        );
    }

    async fn prune_sticky_routes(&self) {
        let now = Instant::now();
        let mut sticky = self.inner.sticky_routes.write().await;
        sticky.retain(|_, route| route.expires_at > now);
        maybe_shrink_hash_map(&mut sticky);
    }

    async fn probe_all(&self) {
        let mut tasks = tokio::task::JoinSet::new();
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            let uplink = Arc::clone(uplink);
            let probe = self.inner.probe.clone();
            let timeout_duration = self.inner.probe.timeout;
            let execution_limit = Arc::clone(&self.inner.probe_execution_limit);
            let dial_limit = Arc::clone(&self.inner.probe_dial_limit);
            tasks.spawn(async move {
                let _permit = execution_limit
                    .acquire_owned()
                    .await
                    .expect("probe execution semaphore closed");
                let outcome = timeout(timeout_duration, probe_uplink(&uplink, &probe, dial_limit))
                    .await
                    .unwrap_or_else(|_| {
                        Err(anyhow!("probe timed out after {:?}", timeout_duration))
                    });
                (index, uplink, outcome)
            });
        }

        while let Some(joined) = tasks.join_next().await {
            let (index, uplink, outcome) = match joined {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, "probe task failed");
                    continue;
                }
            };
            let mut refill_tcp = false;
            let mut refill_udp = false;
            match outcome {
                Ok(result) => {
                    let (tcp_rtt_ewma_ms, udp_rtt_ewma_ms) = {
                        let now = Instant::now();
                        let mut statuses = self.inner.statuses.write().await;
                        let status = &mut statuses[index];
                        status.last_checked = Some(now);
                        status.tcp_healthy = Some(result.tcp_ok);
                        status.udp_healthy = Some(result.udp_ok);
                        status.tcp_latency = result.tcp_latency;
                        status.udp_latency = result.udp_latency;
                        update_rtt_ewma(
                            &mut status.tcp_rtt_ewma,
                            result.tcp_latency,
                            self.inner.load_balancing.rtt_ewma_alpha,
                        );
                        update_rtt_ewma(
                            &mut status.udp_rtt_ewma,
                            result.udp_latency,
                            self.inner.load_balancing.rtt_ewma_alpha,
                        );
                        if !result.tcp_ok {
                            add_penalty(&mut status.tcp_penalty, now, &self.inner.load_balancing);
                        }
                        if !result.udp_ok {
                            add_penalty(&mut status.udp_penalty, now, &self.inner.load_balancing);
                        }
                        status.cooldown_until_tcp = None;
                        status.cooldown_until_udp = None;
                        status.last_error = None;
                        (
                            status
                                .tcp_rtt_ewma
                                .map(|v| v.as_millis() as u64)
                                .unwrap_or_default(),
                            status
                                .udp_rtt_ewma
                                .map(|v| v.as_millis() as u64)
                                .unwrap_or_default(),
                        )
                    };
                    debug!(
                        uplink = %uplink.name,
                        tcp_healthy = result.tcp_ok,
                        udp_healthy = result.udp_ok,
                        tcp_latency_ms = result.tcp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
                        udp_latency_ms = result.udp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
                        tcp_rtt_ewma_ms,
                        udp_rtt_ewma_ms,
                        "uplink probe succeeded"
                    );
                    refill_tcp = result.tcp_ok;
                    refill_udp = result.udp_ok;
                }
                Err(error) => {
                    {
                        let now = Instant::now();
                        let mut statuses = self.inner.statuses.write().await;
                        let status = &mut statuses[index];
                        status.last_checked = Some(now);
                        status.tcp_healthy = Some(false);
                        status.udp_healthy = Some(false);
                        add_penalty(&mut status.tcp_penalty, now, &self.inner.load_balancing);
                        add_penalty(&mut status.udp_penalty, now, &self.inner.load_balancing);
                        status.last_error = Some(format!("{error:#}"));
                    }
                    warn!(uplink = %uplink.name, error = %format!("{error:#}"), "uplink probe failed");
                }
            }

            if refill_tcp {
                self.spawn_refill(index, TransportKind::Tcp);
            } else {
                self.clear_standby(index, TransportKind::Tcp).await;
            }
            if refill_udp {
                self.spawn_refill(index, TransportKind::Udp);
            } else {
                self.clear_standby(index, TransportKind::Udp).await;
            }
        }
    }
}

#[derive(Debug)]
struct ProbeOutcome {
    tcp_ok: bool,
    udp_ok: bool,
    tcp_latency: Option<Duration>,
    udp_latency: Option<Duration>,
}

#[derive(Clone)]
struct CandidateState {
    index: usize,
    uplink: Arc<UplinkConfig>,
    healthy: bool,
    score: Option<Duration>,
}

struct StandbyPool {
    tcp: Mutex<VecDeque<AnyWsStream>>,
    udp: Mutex<VecDeque<AnyWsStream>>,
    tcp_refill: Mutex<()>,
    udp_refill: Mutex<()>,
}

async fn probe_uplink(
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
) -> Result<ProbeOutcome> {
    let (tcp_ok, tcp_latency) = run_tcp_probe(uplink, probe, Arc::clone(&dial_limit)).await?;
    let (udp_ok, udp_latency) = run_udp_probe(uplink, probe, dial_limit).await?;

    Ok(ProbeOutcome {
        tcp_ok,
        udp_ok,
        tcp_latency,
        udp_latency,
    })
}

async fn run_tcp_probe(
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
) -> Result<(bool, Option<Duration>)> {
    let started = Instant::now();
    if probe.ws.enabled {
        let probe_started = Instant::now();
        let result = run_ws_probe(
            &uplink.name,
            "tcp",
            &uplink.tcp_ws_url,
            uplink.tcp_ws_mode,
            uplink.fwmark,
            Arc::clone(&dial_limit),
        )
        .await;
        metrics::record_probe(
            &uplink.name,
            "tcp",
            "ws",
            result.is_ok(),
            probe_started.elapsed(),
        );
        result?;
    }
    if let Some(http_probe) = &probe.http {
        let probe_started = Instant::now();
        let result = run_http_probe(uplink, http_probe, dial_limit).await;
        metrics::record_probe(
            &uplink.name,
            "tcp",
            "http",
            result.is_ok(),
            probe_started.elapsed(),
        );
        let ok = result?;
        return Ok((ok, Some(started.elapsed())));
    }
    if probe.ws.enabled {
        return Ok((true, Some(started.elapsed())));
    }
    Ok((true, None))
}

async fn run_udp_probe(
    uplink: &UplinkConfig,
    probe: &ProbeConfig,
    dial_limit: Arc<Semaphore>,
) -> Result<(bool, Option<Duration>)> {
    let Some(udp_ws_url) = uplink.udp_ws_url.as_ref() else {
        return Ok((false, None));
    };

    let started = Instant::now();
    if probe.ws.enabled {
        let probe_started = Instant::now();
        let result = run_ws_probe(
            &uplink.name,
            "udp",
            udp_ws_url,
            uplink.udp_ws_mode,
            uplink.fwmark,
            Arc::clone(&dial_limit),
        )
        .await;
        metrics::record_probe(
            &uplink.name,
            "udp",
            "ws",
            result.is_ok(),
            probe_started.elapsed(),
        );
        result?;
    }
    if let Some(dns_probe) = &probe.dns {
        let probe_started = Instant::now();
        let result = run_dns_probe(uplink, dns_probe, dial_limit).await;
        metrics::record_probe(
            &uplink.name,
            "udp",
            "dns",
            result.is_ok(),
            probe_started.elapsed(),
        );
        let ok = result?;
        return Ok((ok, Some(started.elapsed())));
    }
    if probe.ws.enabled {
        return Ok((true, Some(started.elapsed())));
    }
    Ok((true, None))
}

async fn run_ws_probe(
    uplink_name: &str,
    transport: &'static str,
    url: &url::Url,
    mode: crate::types::WsTransportMode,
    fwmark: Option<u32>,
    dial_limit: Arc<Semaphore>,
) -> Result<()> {
    let _permit = dial_limit
        .acquire_owned()
        .await
        .expect("probe dial semaphore closed");
    let mut ws_stream = connect_websocket(url, mode, fwmark)
        .await
        .with_context(|| format!("failed to connect WebSocket probe to {url}"))?;

    ping_idle_websocket(&mut ws_stream).await?;
    debug!(
        uplink = %uplink_name,
        transport,
        probe = "ws",
        url = %url,
        "closing probe websocket after successful ping"
    );
    if let Err(error) = ws_stream.close().await {
        debug!(
            uplink = %uplink_name,
            transport,
            probe = "ws",
            url = %url,
            error = %error,
            "probe websocket close returned error during teardown"
        );
    }
    Ok(())
}

async fn ping_idle_websocket(ws_stream: &mut AnyWsStream) -> Result<()> {
    let payload = b"probe".to_vec();
    ws_stream
        .send(Message::Ping(payload.clone().into()))
        .await
        .context("failed to send WebSocket ping")?;

    loop {
        let message = ws_stream
            .next()
            .await
            .ok_or_else(|| anyhow!("websocket probe stream closed before pong"))?
            .context("websocket probe read failed")?;
        match message {
            Message::Pong(bytes) if bytes.as_ref() == payload.as_slice() => return Ok(()),
            Message::Pong(_) => return Ok(()),
            Message::Ping(_) | Message::Binary(_) | Message::Text(_) => continue,
            Message::Close(frame) => bail!("websocket probe received close frame: {:?}", frame),
            Message::Frame(_) => continue,
        }
    }
}

fn is_expected_standby_probe_failure(error: &anyhow::Error) -> bool {
    let lower = format!("{error:#}").to_lowercase();
    lower.contains("websocket probe received close frame")
        || lower.contains("websocket probe stream closed before pong")
        || lower.contains("connection reset by peer")
        || lower.contains("broken pipe")
        || lower.contains("os error 104")
        || lower.contains("os error 54")
        || lower.contains("os error 32")
}

async fn run_http_probe(
    uplink: &UplinkConfig,
    probe: &HttpProbeConfig,
    dial_limit: Arc<Semaphore>,
) -> Result<bool> {
    if probe.url.scheme() != "http" {
        bail!("only http:// probe URLs are currently supported");
    }

    let host = probe
        .url
        .host_str()
        .ok_or_else(|| anyhow!("http probe URL is missing host: {}", probe.url))?;
    let port = probe.url.port_or_known_default().unwrap_or(80);
    let target = if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => TargetAddr::IpV4(v4, port),
            IpAddr::V6(v6) => TargetAddr::IpV6(v6, port),
        }
    } else {
        TargetAddr::Domain(host.to_string(), port)
    };

    let path = {
        let mut path = if probe.url.path().is_empty() {
            "/".to_string()
        } else {
            probe.url.path().to_string()
        };
        if let Some(query) = probe.url.query() {
            path.push('?');
            path.push_str(query);
        }
        path
    };

    let ws_stream = {
        let _permit = dial_limit
            .acquire_owned()
            .await
            .expect("probe dial semaphore closed");
        connect_websocket(&uplink.tcp_ws_url, uplink.tcp_ws_mode, uplink.fwmark)
            .await
            .with_context(|| {
                format!(
                    "failed to connect HTTP probe websocket for uplink {}",
                    uplink.name
                )
            })?
    };
    let (ws_sink, ws_stream) = ws_stream.split();

    let master_key = uplink.cipher.derive_master_key(&uplink.password);
    let mut writer = TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key).await?;
    let mut reader = TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key);
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send HTTP probe target")?;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        format_http_host_header(host, port)
    );
    writer
        .send_chunk(request.as_bytes())
        .await
        .context("failed to send HTTP probe request")?;

    let response = reader
        .read_chunk()
        .await
        .context("failed to read HTTP probe response")?;
    let line = String::from_utf8_lossy(&response);
    let status = line
        .lines()
        .next()
        .and_then(|first| first.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid HTTP probe response status line"))?;

    debug!(
        uplink = %uplink.name,
        transport = "tcp",
        probe = "http",
        url = %probe.url,
        "closing probe websocket after successful HTTP probe"
    );
    if let Err(error) = writer.close().await {
        debug!(
            uplink = %uplink.name,
            transport = "tcp",
            probe = "http",
            url = %probe.url,
            error = %format!("{error:#}"),
            "probe websocket close returned error during teardown"
        );
    }

    Ok((200..400).contains(&status))
}

async fn run_dns_probe(
    uplink: &UplinkConfig,
    probe: &DnsProbeConfig,
    dial_limit: Arc<Semaphore>,
) -> Result<bool> {
    let udp_ws_url = uplink
        .udp_ws_url
        .as_ref()
        .ok_or_else(|| anyhow!("uplink {} has no udp_ws_url for DNS probe", uplink.name))?;

    let transport = {
        let _permit = dial_limit
            .acquire_owned()
            .await
            .expect("probe dial semaphore closed");
        UdpWsTransport::connect(
            udp_ws_url,
            uplink.udp_ws_mode,
            uplink.cipher,
            &uplink.password,
            uplink.fwmark,
        )
        .await
        .with_context(|| {
            format!(
                "failed to connect DNS probe websocket for uplink {}",
                uplink.name
            )
        })?
    };

    let dns_server = probe.target_addr()?;
    let query = build_dns_query(&probe.name);
    let mut payload = dns_server.to_wire_bytes()?;
    payload.extend_from_slice(&query);

    transport
        .send_packet(&payload)
        .await
        .context("failed to send DNS probe packet")?;
    let response = transport
        .read_packet()
        .await
        .context("failed to read DNS probe response")?;
    let (_, consumed) = TargetAddr::from_wire_bytes(&response)?;
    let dns = &response[consumed..];

    if dns.len() < 12 {
        bail!("DNS probe response is too short");
    }
    if dns[..2] != query[..2] {
        bail!("DNS probe transaction id mismatch");
    }
    if dns[3] & 0x0f != 0 {
        bail!("DNS probe returned non-zero rcode");
    }

    debug!(
        uplink = %uplink.name,
        transport = "udp",
        probe = "dns",
        url = %udp_ws_url,
        "closing probe websocket after successful DNS probe"
    );
    if let Err(error) = transport.close().await {
        debug!(
            uplink = %uplink.name,
            transport = "udp",
            probe = "dns",
            url = %udp_ws_url,
            error = %format!("{error:#}"),
            "probe websocket close returned error during teardown"
        );
    }

    Ok(true)
}

fn build_dns_query(name: &str) -> Vec<u8> {
    let txid = 0x5353u16.to_be_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&txid);
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&[0x00, 0x01]);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    out
}

fn format_http_host_header(host: &str, port: u16) -> String {
    let bracketed = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };

    match port {
        80 => bracketed,
        _ => format!("{bracketed}:{port}"),
    }
}

fn effective_health(status: &UplinkStatus, transport: TransportKind, now: Instant) -> bool {
    match transport {
        TransportKind::Tcp => {
            status.tcp_healthy == Some(true)
                && status.cooldown_until_tcp.is_none_or(|until| until <= now)
        }
        TransportKind::Udp => {
            status.udp_healthy == Some(true)
                && status.cooldown_until_udp.is_none_or(|until| until <= now)
        }
    }
}

fn effective_latency(
    status: &UplinkStatus,
    transport: TransportKind,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    let base = scoring_base_latency(status, transport);
    let penalty = current_penalty(
        match transport {
            TransportKind::Tcp => &status.tcp_penalty,
            TransportKind::Udp => &status.udp_penalty,
        },
        now,
        config,
    );
    match (base, penalty) {
        (Some(base), Some(penalty)) => Some(base.saturating_add(penalty)),
        (Some(base), None) => Some(base),
        (None, Some(penalty)) => Some(penalty),
        (None, None) => None,
    }
}

fn scoring_base_latency(status: &UplinkStatus, transport: TransportKind) -> Option<Duration> {
    match transport {
        TransportKind::Tcp => status.tcp_rtt_ewma.or(status.tcp_latency),
        TransportKind::Udp => status.udp_rtt_ewma.or(status.udp_latency),
    }
}

fn score_latency(
    status: &UplinkStatus,
    weight: f64,
    transport: TransportKind,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    let effective = effective_latency(status, transport, now, config)?;
    let weight = weight.max(0.000_001);
    Some(Duration::from_secs_f64(effective.as_secs_f64() / weight))
}

fn update_rtt_ewma(current: &mut Option<Duration>, sample: Option<Duration>, alpha: f64) {
    let Some(sample) = sample else {
        return;
    };
    *current = Some(match *current {
        Some(existing) => Duration::from_secs_f64(
            existing.as_secs_f64() * (1.0 - alpha) + sample.as_secs_f64() * alpha,
        ),
        None => sample,
    });
}

fn current_penalty(
    state: &PenaltyState,
    now: Instant,
    config: &LoadBalancingConfig,
) -> Option<Duration> {
    let updated_at = state.updated_at?;
    if state.value_secs <= 0.0 {
        return None;
    }
    let elapsed = now.saturating_duration_since(updated_at).as_secs_f64();
    let halflife = config.failure_penalty_halflife.as_secs_f64().max(1.0);
    let value_secs = state.value_secs * 0.5_f64.powf(elapsed / halflife);
    if value_secs < 0.001 {
        None
    } else {
        Some(Duration::from_secs_f64(
            value_secs.min(config.failure_penalty_max.as_secs_f64()),
        ))
    }
}

fn add_penalty(state: &mut PenaltyState, now: Instant, config: &LoadBalancingConfig) {
    let current = current_penalty(state, now, config)
        .unwrap_or_default()
        .as_secs_f64();
    let next = (current + config.failure_penalty.as_secs_f64())
        .min(config.failure_penalty_max.as_secs_f64());
    state.value_secs = next;
    state.updated_at = Some(now);
}

fn duration_to_millis_option(value: Option<Duration>) -> Option<u128> {
    value.map(|v| v.as_millis())
}

fn routing_key(transport: TransportKind, target: Option<&TargetAddr>) -> RoutingKey {
    match target {
        Some(target) => format!("{transport:?}:{target}"),
        None => format!("{transport:?}:default"),
    }
}

fn transport_from_key(key: &str) -> TransportKind {
    if key.starts_with("Udp:") {
        TransportKind::Udp
    } else {
        TransportKind::Tcp
    }
}

fn rightless_bool(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

pub fn log_uplink_summary(manager: &UplinkManager) {
    info!(
        uplinks = manager.uplinks().len(),
        sticky_ttl_secs = manager.inner.load_balancing.sticky_ttl.as_secs(),
        hysteresis_ms = manager.inner.load_balancing.hysteresis.as_millis() as u64,
        failure_cooldown_secs = manager.inner.load_balancing.failure_cooldown.as_secs(),
        warm_standby_tcp = manager.inner.load_balancing.warm_standby_tcp,
        warm_standby_udp = manager.inner.load_balancing.warm_standby_udp,
        rtt_ewma_alpha = manager.inner.load_balancing.rtt_ewma_alpha,
        failure_penalty_ms = manager.inner.load_balancing.failure_penalty.as_millis() as u64,
        failure_penalty_max_ms =
            manager.inner.load_balancing.failure_penalty_max.as_millis() as u64,
        failure_penalty_halflife_secs = manager
            .inner
            .load_balancing
            .failure_penalty_halflife
            .as_secs(),
        "uplink manager initialized"
    );
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        PenaltyState, TransportKind, UplinkStatus, effective_latency, score_latency,
        update_rtt_ewma,
    };
    use crate::config::LoadBalancingConfig;
    use tokio::time::Instant;

    fn lb() -> LoadBalancingConfig {
        LoadBalancingConfig {
            sticky_ttl: Duration::from_secs(300),
            hysteresis: Duration::from_millis(50),
            failure_cooldown: Duration::from_secs(10),
            warm_standby_tcp: 0,
            warm_standby_udp: 0,
            rtt_ewma_alpha: 0.25,
            failure_penalty: Duration::from_millis(500),
            failure_penalty_max: Duration::from_secs(30),
            failure_penalty_halflife: Duration::from_secs(60),
        }
    }

    #[test]
    fn rtt_ewma_smooths_new_samples() {
        let mut current = Some(Duration::from_millis(100));
        update_rtt_ewma(&mut current, Some(Duration::from_millis(300)), 0.25);
        assert_eq!(current, Some(Duration::from_millis(150)));
    }

    #[test]
    fn weighted_score_prefers_higher_weight_for_same_latency() {
        let now = Instant::now();
        let status = UplinkStatus {
            tcp_latency: Some(Duration::from_millis(100)),
            tcp_rtt_ewma: Some(Duration::from_millis(100)),
            tcp_penalty: PenaltyState::default(),
            ..UplinkStatus::default()
        };
        let light = score_latency(&status, 1.0, TransportKind::Tcp, now, &lb()).unwrap();
        let heavy = score_latency(&status, 2.0, TransportKind::Tcp, now, &lb()).unwrap();
        assert!(heavy < light);
        assert_eq!(
            effective_latency(&status, TransportKind::Tcp, now, &lb()),
            Some(Duration::from_millis(100))
        );
    }
}
