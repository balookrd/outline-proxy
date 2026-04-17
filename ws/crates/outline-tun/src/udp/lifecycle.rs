use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Result, anyhow, bail};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::utils::maybe_shrink_hash_map;
use outline_metrics as metrics;
use outline_transport::UdpWsTransport;
use socks5_proto::TargetAddr;
use outline_uplink::{TransportKind, UplinkCandidate, UplinkManager};

use super::wire::build_response_packet;
use super::{
    TUN_FLOW_CLEANUP_INTERVAL, TunUdpEngine, UdpFlowKey, UdpFlowState, ip_family_from_version,
    ip_to_target,
};

impl TunUdpEngine {
    pub(super) fn spawn_cleanup_loop(&self) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(TUN_FLOW_CLEANUP_INTERVAL).await;
                engine.cleanup_idle_flows().await;
            }
        });
    }

    pub(super) async fn create_flow(
        &self,
        key: UdpFlowKey,
        manager: &UplinkManager,
    ) -> Result<(u64, Arc<UdpWsTransport>, usize, Arc<str>)> {
        let remote_target = ip_to_target(key.remote_ip, key.remote_port);
        let (candidate, transport) = select_candidate_and_connect(manager, &remote_target).await?;
        manager
            .confirm_selected_uplink(TransportKind::Udp, Some(&remote_target), candidate.index)
            .await;
        let transport = Arc::new(transport);
        let now = Instant::now();
        let flow_id = self
            .inner
            .next_flow_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let state = UdpFlowState {
            id: flow_id,
            transport: Arc::clone(&transport),
            uplink_index: candidate.index,
            uplink_name: Arc::from(candidate.uplink.name.as_str()),
            group_name: Arc::from(manager.group_name()),
            manager: manager.clone(),
            created_at: now,
            last_seen: now,
        };

        let mut evicted_flow = None;
        {
            let mut guard = self.inner.flows.write().await;
            if let Some(existing) = guard.get(&key).map(Arc::clone) {
                drop(guard);
                let mut existing = existing.lock().await;
                existing.last_seen = now;
                return Ok((
                    existing.id,
                    Arc::clone(&existing.transport),
                    existing.uplink_index,
                    existing.uplink_name.clone(),
                ));
            }
            if guard.len() >= self.inner.max_flows {
                if let Some(evicted_key) = oldest_flow_key(&guard).await {
                    if let Some(evicted) = guard.remove(&evicted_key) {
                        {
                            let snapshot = evicted.lock().await;
                            warn!(
                                evicted_flow_id = snapshot.id,
                                evicted_uplink = %snapshot.uplink_name,
                                max_flows = self.inner.max_flows,
                                "evicted oldest TUN UDP flow due to flow table limit"
                            );
                        }
                        evicted_flow = Some(evicted);
                    }
                } else {
                    bail!("TUN flow table limit reached and no flow could be evicted");
                }
            }
            guard.insert(key.clone(), Arc::new(Mutex::new(state)));
        }

        if let Some(flow) = evicted_flow {
            close_udp_flow(flow, "evicted").await;
        }

        metrics::record_uplink_selected("udp", manager.group_name(), &candidate.uplink.name);
        metrics::record_tun_flow_created(manager.group_name(), &candidate.uplink.name);
        debug!(
            flow_id,
            group = %manager.group_name(),
            uplink = %candidate.uplink.name,
            local = %format!("{}:{}", key.local_ip, key.local_port),
            remote = %format!("{}:{}", key.remote_ip, key.remote_port),
            "created TUN UDP flow"
        );
        self.spawn_flow_reader(
            key,
            flow_id,
            Arc::clone(&transport),
            candidate.index,
            manager.clone(),
        );

        Ok((flow_id, transport, candidate.index, Arc::from(candidate.uplink.name.as_str())))
    }

    fn spawn_flow_reader(
        &self,
        key: UdpFlowKey,
        flow_id: u64,
        transport: Arc<UdpWsTransport>,
        uplink_index: usize,
        manager: UplinkManager,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            let result = async {
                loop {
                    if manager.strict_active_uplink_for(TransportKind::Udp)
                        && manager
                            .active_uplink_index_for_transport(TransportKind::Udp)
                            .await
                            .is_some_and(|active| active != uplink_index)
                    {
                        engine.close_flow_if_current(&key, flow_id, "global_switch").await;
                        return Ok(());
                    }
                    let payload = transport.read_packet().await?;
                    let (target, consumed) = TargetAddr::from_wire_bytes(&payload)?;
                    let packet = build_response_packet(
                        key.version,
                        &target,
                        key.local_ip,
                        key.local_port,
                        &payload[consumed..],
                    )?;
                    let uplink_name: Arc<str> = {
                        let handle = engine.inner.flows.read().await.get(&key).map(Arc::clone);
                        match handle {
                            Some(h) => {
                                let flow = h.lock().await;
                                if flow.id == flow_id {
                                    flow.uplink_name.clone()
                                } else {
                                    Arc::from("unknown")
                                }
                            },
                            None => Arc::from("unknown"),
                        }
                    };
                    metrics::add_udp_datagram(
                        "upstream_to_client",
                        manager.group_name(),
                        &uplink_name,
                    );
                    metrics::add_bytes(
                        "udp",
                        "upstream_to_client",
                        manager.group_name(),
                        &uplink_name,
                        payload.len(),
                    );
                    engine.inner.writer.write_packet(&packet).await?;
                    metrics::record_tun_packet(
                        "upstream_to_tun",
                        ip_family_from_version(key.version),
                        "accepted",
                    );
                    let handle = engine.inner.flows.read().await.get(&key).map(Arc::clone);
                    if let Some(handle) = handle {
                        let mut flow = handle.lock().await;
                        if flow.id == flow_id {
                            flow.last_seen = Instant::now();
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            }
            .await;
            let close_reason = if result.is_ok() { "closed" } else { "read_error" };

            if let Err(ref error) = result {
                let is_current = {
                    let handle = engine.inner.flows.read().await.get(&key).map(Arc::clone);
                    match handle {
                        Some(h) => h.lock().await.id == flow_id,
                        None => false,
                    }
                };
                if is_current {
                    report_udp_runtime_failure(&manager, uplink_index, error).await;
                    metrics::record_tun_packet(
                        "upstream_to_tun",
                        ip_family_from_version(key.version),
                        "error",
                    );
                    warn!(
                        flow_id,
                        error = %format!("{error:#}"),
                        "TUN UDP flow reader stopped"
                    );
                }
            }
            engine.close_flow_if_current(&key, flow_id, close_reason).await;
        });
    }

    pub(super) async fn close_flow_if_current(
        &self,
        key: &UdpFlowKey,
        flow_id: u64,
        reason: &'static str,
    ) {
        // Two-stage: first check (read-lock + per-flow lock) without
        // mutating the map, then take the write-lock only if removal is
        // actually warranted. Avoids acquiring the map write-lock on every
        // call from reader tasks that lost the race.
        let should_remove = {
            let handle = self.inner.flows.read().await.get(key).map(Arc::clone);
            match handle {
                Some(h) => h.lock().await.id == flow_id,
                None => return,
            }
        };
        if !should_remove {
            return;
        }
        let removed = {
            let mut guard = self.inner.flows.write().await;
            // Re-check under write-lock: another racer may have replaced this
            // flow between our read-lock drop and write-lock acquire.
            if let Some(handle) = guard.get(key).map(Arc::clone) {
                let same = handle.lock().await.id == flow_id;
                if same { guard.remove(key) } else { None }
            } else {
                None
            }
        };

        if let Some(flow) = removed {
            close_udp_flow(flow, reason).await;
        }
    }

    async fn cleanup_idle_flows(&self) {
        let now = Instant::now();
        let idle_timeout = self.inner.idle_timeout;

        // Collect keys whose last_seen has expired without holding the map
        // write-lock across per-flow locks: read-lock + snapshot Arc clones,
        // then inspect each flow's Mutex individually.
        let expired_keys: Vec<UdpFlowKey> = {
            let handles: Vec<(UdpFlowKey, Arc<Mutex<UdpFlowState>>)> = {
                let guard = self.inner.flows.read().await;
                guard.iter().map(|(k, v)| (k.clone(), Arc::clone(v))).collect()
            };
            let mut expired = Vec::new();
            for (key, handle) in handles {
                let flow = handle.lock().await;
                if now.saturating_duration_since(flow.last_seen) >= idle_timeout {
                    expired.push(key);
                }
            }
            expired
        };

        let expired_flows = {
            let mut guard = self.inner.flows.write().await;
            let mut removed = Vec::with_capacity(expired_keys.len());
            for key in expired_keys {
                if let Some(flow) = guard.remove(&key) {
                    removed.push(flow);
                }
            }
            maybe_shrink_hash_map(&mut guard);
            removed
        };

        for flow in expired_flows {
            close_udp_flow(flow, "idle_timeout").await;
        }

        // Clean up idle direct-routed flows — same pattern.
        let direct_expired_keys: Vec<super::UdpFlowKey> = {
            let handles: Vec<(UdpFlowKey, Arc<Mutex<super::types::DirectUdpFlowState>>)> = {
                let guard = self.inner.direct_flows.read().await;
                guard.iter().map(|(k, v)| (k.clone(), Arc::clone(v))).collect()
            };
            let mut expired = Vec::new();
            for (key, handle) in handles {
                let flow = handle.lock().await;
                if now.saturating_duration_since(flow.last_seen) >= idle_timeout {
                    expired.push(key);
                }
            }
            expired
        };
        {
            let mut direct = self.inner.direct_flows.write().await;
            for key in direct_expired_keys {
                if let Some(flow_handle) = direct.remove(&key) {
                    let flow = flow_handle.lock().await;
                    flow._reader.abort();
                    metrics::record_tun_flow_closed(
                        metrics::DIRECT_GROUP_LABEL,
                        metrics::DIRECT_UPLINK_LABEL,
                        "idle_timeout",
                        now.saturating_duration_since(flow.created_at),
                    );
                }
            }
        }
    }

    pub(super) async fn recreate_flow_after_send_error(
        &self,
        key: &UdpFlowKey,
        flow_id: u64,
        uplink_index: usize,
        uplink_name: &str,
        manager: &UplinkManager,
        error: &anyhow::Error,
    ) -> Result<(u64, Arc<UdpWsTransport>, usize, Arc<str>)> {
        report_udp_runtime_failure(manager, uplink_index, error).await;
        self.close_flow_if_current(key, flow_id, "send_error").await;
        let replacement = self.create_flow(key.clone(), manager).await?;
        metrics::record_failover("udp", manager.group_name(), uplink_name, &replacement.3);
        Ok(replacement)
    }
}

async fn report_udp_runtime_failure(
    manager: &UplinkManager,
    uplink_index: usize,
    error: &anyhow::Error,
) {
    manager
        .report_runtime_failure(uplink_index, TransportKind::Udp, error)
        .await;
}

async fn select_candidate_and_connect(
    manager: &UplinkManager,
    remote_target: &TargetAddr,
) -> Result<(UplinkCandidate, UdpWsTransport)> {
    let mut last_error = None;
    let strict_transport = manager.strict_active_uplink_for(TransportKind::Udp);
    let candidates = manager.udp_candidates(Some(remote_target)).await;
    let iter = if strict_transport {
        candidates.into_iter().take(1).collect::<Vec<_>>()
    } else {
        candidates
    };
    for candidate in iter {
        match manager.acquire_udp_standby_or_connect(&candidate, "tun_udp").await {
            Ok(transport) => return Ok((candidate, transport)),
            Err(error) => {
                report_udp_runtime_failure(manager, candidate.index, &error).await;
                last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
            },
        }
    }
    Err(anyhow!(
        "all UDP uplinks failed for TUN flow: {}",
        last_error.unwrap_or_else(|| "no UDP-capable uplinks available".to_string())
    ))
}

async fn oldest_flow_key(
    flows: &HashMap<UdpFlowKey, Arc<Mutex<UdpFlowState>>>,
) -> Option<UdpFlowKey> {
    let mut oldest: Option<(UdpFlowKey, Instant)> = None;
    for (key, handle) in flows {
        let last_seen = handle.lock().await.last_seen;
        match &oldest {
            Some((_, t)) if last_seen >= *t => continue,
            _ => oldest = Some((key.clone(), last_seen)),
        }
    }
    oldest.map(|(k, _)| k)
}

pub(crate) async fn close_udp_flow(
    flow: Arc<Mutex<UdpFlowState>>,
    reason: &'static str,
) {
    // Lock briefly to snapshot the fields we need, then release so the
    // async `transport.close()` does not hold the per-flow Mutex.
    let (id, transport, group, uplink, created_at) = {
        let guard = flow.lock().await;
        (
            guard.id,
            Arc::clone(&guard.transport),
            guard.group_name.clone(),
            guard.uplink_name.clone(),
            guard.created_at,
        )
    };
    metrics::record_tun_flow_closed(
        &group,
        &uplink,
        reason,
        Instant::now().saturating_duration_since(created_at),
    );
    if let Err(error) = transport.close().await {
        debug!(
            flow_id = id,
            reason,
            error = %format!("{error:#}"),
            "failed to close TUN UDP transport"
        );
    }
}
