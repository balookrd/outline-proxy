use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::memory::maybe_shrink_hash_map;
use crate::metrics;
use crate::transport::{UdpWsTransport, is_dropped_oversized_udp_error};
use crate::tun::SharedTunWriter;
use crate::types::TargetAddr;
use crate::uplink::{TransportKind, UplinkCandidate, UplinkManager};

const TUN_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
mod wire;

pub(crate) use self::wire::parse_udp_packet;
use self::wire::{IpVersion, ParsedUdpPacket, build_response_packet};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    version: IpVersion,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Clone)]
struct UdpFlowState {
    id: u64,
    transport: Arc<UdpWsTransport>,
    uplink_index: usize,
    uplink_name: String,
    created_at: Instant,
    last_seen: Instant,
}

type FlowTable = Arc<Mutex<HashMap<UdpFlowKey, UdpFlowState>>>;

#[derive(Clone)]
pub struct TunUdpEngine {
    inner: Arc<TunUdpEngineInner>,
}

struct TunUdpEngineInner {
    writer: SharedTunWriter,
    uplinks: UplinkManager,
    flows: FlowTable,
    next_flow_id: AtomicU64,
    max_flows: usize,
    idle_timeout: Duration,
}

impl TunUdpEngine {
    pub(crate) fn new(
        writer: SharedTunWriter,
        uplinks: UplinkManager,
        max_flows: usize,
        idle_timeout: Duration,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(TunUdpEngineInner {
                writer,
                uplinks,
                flows: Arc::new(Mutex::new(HashMap::new())),
                next_flow_id: AtomicU64::new(1),
                max_flows,
                idle_timeout,
            }),
        };
        engine.spawn_cleanup_loop();
        engine
    }

    pub(crate) async fn handle_packet(&self, packet: ParsedUdpPacket) -> Result<()> {
        let remote_target = ip_to_target(packet.destination_ip, packet.destination_port);
        let key = UdpFlowKey {
            version: packet.version,
            local_ip: packet.source_ip,
            local_port: packet.source_port,
            remote_ip: packet.destination_ip,
            remote_port: packet.destination_port,
        };

        let active_uplink = if self
            .inner
            .uplinks
            .strict_active_uplink_for(TransportKind::Udp)
        {
            self.inner
                .uplinks
                .active_uplink_index_for_transport(TransportKind::Udp)
                .await
        } else {
            None
        };

        let (existing, stale_flow) = {
            let mut guard = self.inner.flows.lock().await;
            match guard.get(&key) {
                Some(flow) if active_uplink.is_some_and(|active| active != flow.uplink_index) => {
                    let stale = guard.remove(&key).expect("stale TUN UDP flow must exist");
                    (None, Some(stale))
                }
                Some(_) => {
                    let flow = guard.get_mut(&key).expect("TUN UDP flow must still exist");
                    flow.last_seen = Instant::now();
                    (
                        Some((
                            flow.id,
                            Arc::clone(&flow.transport),
                            flow.uplink_index,
                            flow.uplink_name.clone(),
                        )),
                        None,
                    )
                }
                None => (None, None),
            }
        };

        if let Some(stale_flow) = stale_flow {
            metrics::record_tun_flow_closed(
                &stale_flow.uplink_name,
                "global_switch",
                Instant::now().saturating_duration_since(stale_flow.created_at),
            );
            if let Err(error) = stale_flow.transport.close().await {
                debug!(
                    flow_id = stale_flow.id,
                    error = %format!("{error:#}"),
                    "failed to close stale TUN UDP transport after global switch"
                );
            }
        }

        let (flow_id, transport, uplink_index, uplink_name) = match existing {
            Some(existing) => existing,
            None => self.create_flow(key.clone()).await?,
        };

        let payload = build_udp_payload(&remote_target, &packet.payload)?;
        if let Err(error) = transport.send_packet(&payload).await {
            if is_dropped_oversized_udp_error(&error) {
                return Ok(());
            }
            self.inner
                .uplinks
                .report_runtime_failure(uplink_index, TransportKind::Udp, &error)
                .await;
            self.close_flow_if_current(&key, flow_id, "send_error")
                .await;
            let (replacement_flow_id, replacement_transport, replacement_index, replacement_name) =
                self.create_flow(key.clone()).await?;
            metrics::record_failover("udp", &uplink_name, &replacement_name);
            if let Err(error) = replacement_transport.send_packet(&payload).await {
                if is_dropped_oversized_udp_error(&error) {
                    return Ok(());
                }
                return Err(error);
            }
            metrics::add_udp_datagram("client_to_upstream", &replacement_name);
            metrics::add_bytes(
                "udp",
                "client_to_upstream",
                &replacement_name,
                payload.len(),
            );
            debug!(
                flow_id = replacement_flow_id,
                uplink = %replacement_name,
                "recreated TUN UDP flow after send failure"
            );
            let _ = replacement_index;
        } else {
            metrics::add_udp_datagram("client_to_upstream", &uplink_name);
            metrics::add_bytes("udp", "client_to_upstream", &uplink_name, payload.len());
        }

        Ok(())
    }

    fn spawn_cleanup_loop(&self) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(TUN_FLOW_CLEANUP_INTERVAL).await;
                engine.cleanup_idle_flows().await;
            }
        });
    }

    async fn create_flow(
        &self,
        key: UdpFlowKey,
    ) -> Result<(u64, Arc<UdpWsTransport>, usize, String)> {
        let remote_target = ip_to_target(key.remote_ip, key.remote_port);
        let (candidate, transport) = self.select_candidate_and_connect(&remote_target).await?;
        self.inner
            .uplinks
            .confirm_selected_uplink(TransportKind::Udp, Some(&remote_target), candidate.index)
            .await;
        let transport = Arc::new(transport);
        let now = Instant::now();
        let flow_id = self.inner.next_flow_id.fetch_add(1, Ordering::Relaxed);
        let state = UdpFlowState {
            id: flow_id,
            transport: Arc::clone(&transport),
            uplink_index: candidate.index,
            uplink_name: candidate.uplink.name.clone(),
            created_at: now,
            last_seen: now,
        };

        let mut evicted_transport = None;
        {
            let mut guard = self.inner.flows.lock().await;
            if let Some(existing) = guard.get_mut(&key) {
                existing.last_seen = now;
                return Ok((
                    existing.id,
                    Arc::clone(&existing.transport),
                    existing.uplink_index,
                    existing.uplink_name.clone(),
                ));
            }
            if guard.len() >= self.inner.max_flows {
                if let Some(evicted_key) = oldest_flow_key(&guard) {
                    if let Some(evicted) = guard.remove(&evicted_key) {
                        metrics::record_tun_flow_closed(
                            &evicted.uplink_name,
                            "evicted",
                            now.saturating_duration_since(evicted.created_at),
                        );
                        warn!(
                            evicted_flow_id = evicted.id,
                            evicted_uplink = %evicted.uplink_name,
                            max_flows = self.inner.max_flows,
                            "evicted oldest TUN UDP flow due to flow table limit"
                        );
                        evicted_transport = Some(evicted.transport);
                    }
                } else {
                    bail!("TUN flow table limit reached and no flow could be evicted");
                }
            }
            guard.insert(key.clone(), state);
        }

        if let Some(transport) = evicted_transport {
            if let Err(error) = transport.close().await {
                debug!(
                    error = %format!("{error:#}"),
                    "failed to close evicted TUN UDP transport"
                );
            }
        }

        metrics::record_uplink_selected("udp", &candidate.uplink.name);
        metrics::record_tun_flow_created(&candidate.uplink.name);
        debug!(
            flow_id,
            uplink = %candidate.uplink.name,
            local = %format!("{}:{}", key.local_ip, key.local_port),
            remote = %format!("{}:{}", key.remote_ip, key.remote_port),
            "created TUN UDP flow"
        );
        self.spawn_flow_reader(key, flow_id, Arc::clone(&transport), candidate.index);

        Ok((
            flow_id,
            transport,
            candidate.index,
            candidate.uplink.name.clone(),
        ))
    }

    async fn select_candidate_and_connect(
        &self,
        remote_target: &TargetAddr,
    ) -> Result<(UplinkCandidate, UdpWsTransport)> {
        let mut last_error = None;
        let strict_transport = self
            .inner
            .uplinks
            .strict_active_uplink_for(TransportKind::Udp);
        let candidates = self.inner.uplinks.udp_candidates(Some(remote_target)).await;
        let iter = if strict_transport {
            candidates.into_iter().take(1).collect::<Vec<_>>()
        } else {
            candidates
        };
        for candidate in iter {
            match self
                .inner
                .uplinks
                .acquire_udp_standby_or_connect(&candidate, "tun_udp")
                .await
            {
                Ok(transport) => return Ok((candidate, transport)),
                Err(error) => {
                    self.inner
                        .uplinks
                        .report_runtime_failure(candidate.index, TransportKind::Udp, &error)
                        .await;
                    last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                }
            }
        }
        Err(anyhow!(
            "all UDP uplinks failed for TUN flow: {}",
            last_error.unwrap_or_else(|| "no UDP-capable uplinks available".to_string())
        ))
    }

    fn spawn_flow_reader(
        &self,
        key: UdpFlowKey,
        flow_id: u64,
        transport: Arc<UdpWsTransport>,
        uplink_index: usize,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            let result = async {
                loop {
                    if engine
                        .inner
                        .uplinks
                        .strict_active_uplink_for(TransportKind::Udp)
                        && engine
                            .inner
                            .uplinks
                            .active_uplink_index_for_transport(TransportKind::Udp)
                            .await
                            .is_some_and(|active| active != uplink_index)
                    {
                        engine
                            .close_flow_if_current(&key, flow_id, "global_switch")
                            .await;
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
                    let uplink_name = {
                        let guard = engine.inner.flows.lock().await;
                        guard
                            .get(&key)
                            .filter(|flow| flow.id == flow_id)
                            .map(|flow| flow.uplink_name.clone())
                            .unwrap_or_else(|| "unknown".to_string())
                    };
                    metrics::add_udp_datagram("upstream_to_client", &uplink_name);
                    metrics::add_bytes("udp", "upstream_to_client", &uplink_name, payload.len());
                    engine.inner.writer.write_packet(&packet).await?;
                    metrics::record_tun_packet(
                        "upstream_to_tun",
                        ip_family_from_version(key.version),
                        "accepted",
                    );
                    let mut guard = engine.inner.flows.lock().await;
                    if let Some(flow) = guard.get_mut(&key) {
                        if flow.id == flow_id {
                            flow.last_seen = Instant::now();
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), anyhow::Error>(())
            }
            .await;
            let close_reason = if result.is_ok() {
                "closed"
            } else {
                "read_error"
            };

            if let Err(ref error) = result {
                let is_current = engine
                    .inner
                    .flows
                    .lock()
                    .await
                    .get(&key)
                    .map_or(false, |f| f.id == flow_id);
                if is_current {
                    engine
                        .inner
                        .uplinks
                        .report_runtime_failure(uplink_index, TransportKind::Udp, error)
                        .await;
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
            engine
                .close_flow_if_current(&key, flow_id, close_reason)
                .await;
        });
    }

    async fn close_flow_if_current(&self, key: &UdpFlowKey, flow_id: u64, reason: &'static str) {
        let removed = {
            let mut guard = self.inner.flows.lock().await;
            if guard.get(key).map(|flow| flow.id) == Some(flow_id) {
                guard.remove(key)
            } else {
                None
            }
        };

        if let Some(flow) = removed {
            metrics::record_tun_flow_closed(
                &flow.uplink_name,
                reason,
                Instant::now().saturating_duration_since(flow.created_at),
            );
            if let Err(error) = flow.transport.close().await {
                debug!(
                    flow_id,
                    reason,
                    error = %format!("{error:#}"),
                    "failed to close TUN UDP transport"
                );
            }
        }
    }

    async fn cleanup_idle_flows(&self) {
        let now = Instant::now();
        let expired = {
            let mut guard = self.inner.flows.lock().await;
            let expired_keys: Vec<UdpFlowKey> = guard
                .iter()
                .filter_map(|(key, flow)| {
                    (now.saturating_duration_since(flow.last_seen) >= self.inner.idle_timeout)
                        .then(|| key.clone())
                })
                .collect();

            let mut removed = Vec::with_capacity(expired_keys.len());
            for key in expired_keys {
                if let Some(flow) = guard.remove(&key) {
                    removed.push(flow);
                }
            }
            maybe_shrink_hash_map(&mut guard);
            removed
        };

        for flow in expired {
            metrics::record_tun_flow_closed(
                &flow.uplink_name,
                "idle_timeout",
                now.saturating_duration_since(flow.created_at),
            );
            if let Err(error) = flow.transport.close().await {
                debug!(
                    flow_id = flow.id,
                    error = %format!("{error:#}"),
                    "failed to close idle TUN UDP transport"
                );
            }
        }
    }
}

pub(crate) fn classify_tun_udp_forward_error(error: &anyhow::Error) -> &'static str {
    let text = format!("{error:#}");
    let lower = text.to_ascii_lowercase();
    if lower.contains("all udp uplinks failed") {
        "all_uplinks_failed"
    } else if lower.contains("failed to send udp websocket frame")
        || lower.contains("websocket read failed")
    {
        "transport_error"
    } else if lower.contains("failed to connect to") {
        "connect_failed"
    } else {
        "other"
    }
}

fn build_udp_payload(target: &TargetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = target.to_wire_bytes()?;
    out.extend_from_slice(payload);
    Ok(out)
}

fn ip_to_target(ip: IpAddr, port: u16) -> TargetAddr {
    match ip {
        IpAddr::V4(ip) => TargetAddr::IpV4(ip, port),
        IpAddr::V6(ip) => TargetAddr::IpV6(ip, port),
    }
}

fn ip_family_from_version(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "ipv4",
        IpVersion::V6 => "ipv6",
    }
}

fn oldest_flow_key(flows: &HashMap<UdpFlowKey, UdpFlowState>) -> Option<UdpFlowKey> {
    flows
        .iter()
        .min_by_key(|(_, flow)| flow.last_seen)
        .map(|(key, _)| key.clone())
}

#[cfg(test)]
mod tests {
    use super::wire::{build_ipv4_udp_packet, build_ipv6_udp_packet};
    use super::{IpVersion, parse_udp_packet};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_udp_roundtrip() {
        let packet = build_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            40000,
            b"hello",
        )
        .unwrap();

        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V4);
        assert_eq!(parsed.source_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(parsed.source_port, 53);
        assert_eq!(parsed.destination_port, 40000);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn ipv6_udp_roundtrip() {
        let packet = build_ipv6_udp_packet(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            5353,
            41000,
            b"world",
        )
        .unwrap();

        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.version, IpVersion::V6);
        assert_eq!(parsed.source_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            parsed.destination_ip,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))
        );
        assert_eq!(parsed.source_port, 5353);
        assert_eq!(parsed.destination_port, 41000);
        assert_eq!(parsed.payload, b"world");
    }
}
