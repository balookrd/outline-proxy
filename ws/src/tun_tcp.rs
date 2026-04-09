use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::atomic_counter::CounterU64;
use anyhow::{Result, anyhow, bail};
use tokio::sync::{Mutex, Notify, RwLock, watch};
use tokio::time::{sleep_until, timeout};
use tracing::{debug, info, warn};

use crate::config::TunTcpConfig;
use crate::memory::maybe_shrink_hash_map;
use crate::metrics;
use crate::transport::TcpShadowsocksReader;
use crate::tun::SharedTunWriter;
use crate::tun_wire::IpVersion;
use crate::types::TargetAddr;
use crate::uplink::{TransportKind, UplinkManager};

pub(crate) const TCP_FLAG_FIN: u8 = 0x01;
pub(crate) const TCP_FLAG_SYN: u8 = 0x02;
pub(crate) const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
pub(crate) const TCP_FLAG_ACK: u8 = 0x10;
const TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL: Duration = Duration::from_secs(1);
const TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL: Duration = Duration::from_secs(30);
const TCP_FAST_RETRANSMIT_DUP_ACKS: u8 = 3;
const MAX_SERVER_SEGMENT_PAYLOAD: usize = 1200;
const TCP_SERVER_RECV_WINDOW_CAPACITY: usize = 262_144;
const TCP_SERVER_WINDOW_SCALE: u8 = 2;
const TCP_INITIAL_RTO: Duration = Duration::from_secs(1);
const TCP_MIN_RTO: Duration = Duration::from_millis(200);
const TCP_MAX_RTO: Duration = Duration::from_secs(60);
const TCP_INITIAL_CWND_SEGMENTS: usize = 10;
const TCP_MIN_SSTHRESH: usize = MAX_SERVER_SEGMENT_PAYLOAD * 2;
const TCP_TIME_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

mod maintenance;
mod state_machine;
#[cfg(test)]
mod tests;
mod upstream;
mod validation;
mod wire;

use self::maintenance::{FlowMaintenancePlan, plan_flow_maintenance, sync_flow_metrics_and_wake};
use self::upstream::{
    close_upstream_writer, ip_family_from_version, ip_to_target, key_uplink_name,
    select_tcp_candidate_and_connect,
};
use self::validation::{PacketValidation, validate_existing_packet};
#[cfg(test)]
pub(crate) use self::wire::parse_tcp_packet as parse_tcp_packet_for_tests;
#[cfg(test)]
use self::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN};
use self::wire::{
    ParsedTcpPacket, build_reset_response, build_response_packet_custom, parse_tcp_packet,
};

#[cfg(test)]
use self::state_machine::{
    BufferedClientSegment, ClientSegmentView, ServerSegment, drain_ready_buffered_segments,
    maybe_emit_zero_window_probe, note_congestion_event, queue_future_segment,
};
use self::state_machine::{
    ServerFlush, TcpFlowState, TcpFlowStatus, apply_client_segment, assess_server_backlog_pressure,
    build_flow_ack_packet, build_flow_packet, build_flow_syn_ack_packet, clear_flow_metrics,
    client_fin_seen, decode_client_window, drain_ready_buffered_segments_from_state,
    exceeds_client_reassembly_limits, flush_server_output, is_duplicate_syn,
    normalize_client_segment, note_ack_progress, note_recent_client_timestamp, process_server_ack,
    queue_future_segment_with_recv_window, reset_zero_window_persist, retransmit_budget_exhausted,
    retransmit_oldest_unacked_packet, seq_gt, seq_lt, server_fin_awaiting_ack, server_fin_sent,
    set_flow_status, transition_on_client_fin, transition_on_server_fin_ack,
    trim_packet_to_receive_window, update_client_send_window,
};

#[derive(Clone)]
pub struct TunTcpEngine {
    inner: Arc<TunTcpEngineInner>,
}

struct TunTcpEngineInner {
    writer: SharedTunWriter,
    uplinks: UplinkManager,
    flows: RwLock<HashMap<TcpFlowKey, Arc<Mutex<TcpFlowState>>>>,
    pending_connects: Mutex<HashSet<TcpFlowKey>>,
    next_flow_id: CounterU64,
    max_flows: usize,
    idle_timeout: Duration,
    tcp: TunTcpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    version: IpVersion,
    client_ip: IpAddr,
    client_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

impl TunTcpEngine {
    pub(crate) fn new(
        writer: SharedTunWriter,
        uplinks: UplinkManager,
        max_flows: usize,
        idle_timeout: Duration,
        tcp: TunTcpConfig,
    ) -> Self {
        let engine = Self {
            inner: Arc::new(TunTcpEngineInner {
                writer,
                uplinks,
                flows: RwLock::new(HashMap::new()),
                pending_connects: Mutex::new(HashSet::new()),
                next_flow_id: CounterU64::new(1),
                max_flows,
                idle_timeout,
                tcp,
            }),
        };
        engine
    }

    pub async fn handle_packet(&self, packet: &[u8]) -> Result<()> {
        let parsed = parse_tcp_packet(packet)?;
        let key = TcpFlowKey {
            version: parsed.version,
            client_ip: parsed.source_ip,
            client_port: parsed.source_port,
            remote_ip: parsed.destination_ip,
            remote_port: parsed.destination_port,
        };
        let ip_family = ip_family_from_version(parsed.version);
        let flow = self.lookup_flow(&key).await;
        match flow {
            Some(flow) => self.handle_existing_flow(flow, parsed).await,
            None if (parsed.flags & TCP_FLAG_RST) != 0 => {
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_rst_observed");
                Ok(())
            }
            None => self.handle_new_flow(key, parsed).await,
        }
    }

    async fn lookup_flow(&self, key: &TcpFlowKey) -> Option<Arc<Mutex<TcpFlowState>>> {
        self.inner.flows.read().await.get(key).cloned()
    }

    async fn write_tun_packet_or_close_flow(&self, key: &TcpFlowKey, packet: &[u8]) -> Result<()> {
        if let Err(error) = self.inner.writer.write_packet(packet).await {
            self.close_flow(key, "write_tun_error").await;
            return Err(error);
        }
        Ok(())
    }

    async fn write_ack_packet_with_event(
        &self,
        key: &TcpFlowKey,
        ack: Vec<u8>,
        ip_family: &'static str,
        uplink_name: &str,
        event: &'static str,
    ) -> Result<()> {
        self.write_tun_packet_or_close_flow(key, &ack).await?;
        metrics::record_tun_tcp_event(uplink_name, event);
        metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
        Ok(())
    }

    async fn report_tcp_runtime_failure(&self, uplink_index: usize, error: &anyhow::Error) {
        if uplink_index == usize::MAX {
            return;
        }
        self.inner
            .uplinks
            .report_runtime_failure(uplink_index, TransportKind::Tcp, error)
            .await;
    }

    async fn report_tcp_runtime_failure_and_abort(
        &self,
        key: &TcpFlowKey,
        uplink_index: usize,
        error: &anyhow::Error,
        reason: &'static str,
    ) {
        self.report_tcp_runtime_failure(uplink_index, error).await;
        self.abort_flow_with_rst(key, reason).await;
    }

    async fn abort_flow_with_rst(&self, key: &TcpFlowKey, reason: &'static str) {
        let flow = self.inner.flows.write().await.remove(key);
        let Some(flow) = flow else {
            return;
        };

        let (flow_id, uplink_name, _duration, upstream_writer, close_signal, rst_packet) = {
            let mut state = flow.lock().await;
            let rst_packet = if matches!(state.status, TcpFlowStatus::Closed) {
                None
            } else {
                build_flow_packet(
                    &state,
                    state.server_seq,
                    state.client_next_seq,
                    TCP_FLAG_RST | TCP_FLAG_ACK,
                    &[],
                )
                .ok()
            };
            state.status = TcpFlowStatus::Closed;
            clear_flow_metrics(&mut state);
            (
                state.id,
                state.uplink_name.clone(),
                state.created_at.elapsed(),
                state.upstream_writer.clone(),
                state.close_signal.clone(),
                rst_packet,
            )
        };

        let _ = close_signal.send(true);
        if let Some(packet) = rst_packet {
            let _ = self.inner.writer.write_packet(&packet).await;
            metrics::record_tun_packet(
                "upstream_to_tun",
                ip_family_from_version(key.version),
                "tcp_rst",
            );
        }
        close_upstream_writer(upstream_writer).await;
        metrics::record_tun_tcp_event(&uplink_name, reason);
        debug!(flow_id, uplink = %uplink_name, reason, "aborted TUN TCP flow");
        self.maybe_shrink_flow_table().await;
    }

    async fn handle_new_flow(&self, key: TcpFlowKey, packet: ParsedTcpPacket) -> Result<()> {
        if (packet.flags & TCP_FLAG_SYN) == 0 || (packet.flags & TCP_FLAG_ACK) != 0 {
            let reset = build_reset_response(&packet)?;
            self.inner.writer.write_packet(&reset).await?;
            metrics::record_tun_packet(
                "upstream_to_tun",
                ip_family_from_version(packet.version),
                "tcp_rst",
            );
            return Ok(());
        }

        if !self.begin_pending_connect(key.clone()).await {
            debug!(remote = %ip_to_target(key.remote_ip, key.remote_port), "ignoring duplicate SYN while TUN TCP connect is already in progress");
            return Ok(());
        }

        let target = ip_to_target(key.remote_ip, key.remote_port);
        let server_isn = rand::random::<u32>();
        let flow_id = self.inner.next_flow_id.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let (close_signal, close_rx) = watch::channel(false);
        let maintenance_notify = Arc::new(Notify::new());
        let state = Arc::new(Mutex::new(TcpFlowState {
            id: flow_id,
            key: key.clone(),
            uplink_index: usize::MAX,
            uplink_name: "connecting".to_string(),
            upstream_writer: None,
            close_signal,
            maintenance_notify,
            status: TcpFlowStatus::SynReceived,
            client_next_seq: packet.sequence_number.wrapping_add(1),
            client_window_scale: packet.window_scale.unwrap_or(0),
            client_sack_permitted: packet.sack_permitted,
            client_max_segment_size: packet.max_segment_size,
            timestamps_enabled: packet.timestamp_value.is_some(),
            recent_client_timestamp: packet.timestamp_value,
            server_timestamp_offset: rand::random::<u32>(),
            client_window: u32::from(packet.window_size),
            client_window_end: server_isn
                .wrapping_add(1)
                .wrapping_add(decode_client_window(
                    &packet,
                    packet.window_scale.unwrap_or(0),
                )),
            client_window_update_seq: packet.sequence_number,
            client_window_update_ack: packet.acknowledgement_number,
            server_seq: server_isn.wrapping_add(1),
            last_client_ack: packet.sequence_number.wrapping_add(1),
            duplicate_ack_count: 0,
            fast_recovery_end: None,
            receive_window_capacity: self.inner.tcp.max_buffered_client_bytes,
            smoothed_rtt: None,
            rttvar: TCP_INITIAL_RTO / 2,
            retransmission_timeout: TCP_INITIAL_RTO,
            congestion_window: MAX_SERVER_SEGMENT_PAYLOAD * TCP_INITIAL_CWND_SEGMENTS,
            slow_start_threshold: TCP_SERVER_RECV_WINDOW_CAPACITY,
            pending_server_data: VecDeque::new(),
            backlog_limit_exceeded_since: None,
            last_ack_progress_at: now,
            pending_client_data: VecDeque::new(),
            unacked_server_segments: VecDeque::new(),
            sack_scoreboard: Vec::new(),
            pending_client_segments: VecDeque::new(),
            server_fin_pending: false,
            zero_window_probe_backoff: TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL,
            next_zero_window_probe_at: None,
            reported_inflight_segments: 0,
            reported_inflight_bytes: 0,
            reported_pending_server_bytes: 0,
            reported_buffered_client_segments: 0,
            reported_zero_window: false,
            reported_backlog_pressure: false,
            reported_backlog_pressure_us: 0,
            reported_ack_progress_stall: false,
            reported_ack_progress_stall_us: 0,
            reported_active: false,
            reported_congestion_window: 0,
            reported_slow_start_threshold: 0,
            reported_retransmission_timeout_us: 0,
            reported_smoothed_rtt_us: 0,
            created_at: now,
            status_since: now,
            last_seen: now,
        }));

        if let Err(error) = self.insert_flow(key.clone(), Arc::clone(&state)).await {
            self.finish_pending_connect(&key).await;
            return Err(error);
        }
        self.finish_pending_connect(&key).await;

        let syn_ack = {
            let mut state = state.lock().await;
            sync_flow_metrics_and_wake(&mut state);
            build_flow_syn_ack_packet(&state, server_isn, packet.sequence_number.wrapping_add(1))?
        };
        self.write_tun_packet_or_close_flow(&key, &syn_ack).await?;
        metrics::record_tun_packet(
            "upstream_to_tun",
            ip_family_from_version(packet.version),
            "tcp_synack",
        );
        self.spawn_flow_maintenance(key.clone(), state.clone(), close_rx.clone());
        self.spawn_upstream_connect(
            key,
            target,
            flow_id,
            state,
            close_rx,
            ip_family_from_version(packet.version),
        );
        Ok(())
    }

    async fn begin_pending_connect(&self, key: TcpFlowKey) -> bool {
        let mut guard = self.inner.pending_connects.lock().await;
        guard.insert(key)
    }

    async fn finish_pending_connect(&self, key: &TcpFlowKey) {
        self.inner.pending_connects.lock().await.remove(key);
    }

    async fn insert_flow(&self, key: TcpFlowKey, flow: Arc<Mutex<TcpFlowState>>) -> Result<()> {
        if self.inner.flows.read().await.len() >= self.inner.max_flows {
            if let Some(evicted_key) = self.oldest_flow_key().await {
                self.abort_flow_with_rst(&evicted_key, "evicted").await;
            } else {
                bail!("TUN TCP flow table limit reached and no flow could be evicted");
            }
        }

        let uplink_name = {
            let state = flow.lock().await;
            state.uplink_name.clone()
        };
        {
            let mut guard = self.inner.flows.write().await;
            guard.insert(key, flow);
        }
        metrics::record_tun_tcp_event(&uplink_name, "flow_created");

        Ok(())
    }

    fn spawn_flow_maintenance(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            let maintenance_notify = { flow.lock().await.maintenance_notify.clone() };
            loop {
                let plan = {
                    let mut state = flow.lock().await;
                    if state.status == TcpFlowStatus::Closed {
                        return;
                    }
                    plan_flow_maintenance(
                        &mut state,
                        &engine.inner.tcp,
                        engine.inner.idle_timeout,
                        Instant::now(),
                    )
                };

                match plan {
                    Ok(FlowMaintenancePlan::Abort(reason)) => {
                        engine.abort_flow_with_rst(&key, reason).await;
                        return;
                    }
                    Ok(FlowMaintenancePlan::Close(reason)) => {
                        engine.close_flow(&key, reason).await;
                        return;
                    }
                    Ok(FlowMaintenancePlan::SendPacket {
                        packet,
                        packet_metric,
                        event,
                    }) => {
                        let ip_family = ip_family_from_version(key.version);
                        if let Err(error) = engine.inner.writer.write_packet(&packet).await {
                            warn!(
                                error = %format!("{error:#}"),
                                "failed to write maintenance TUN TCP packet"
                            );
                            engine.close_flow(&key, "write_tun_error").await;
                            return;
                        }
                        let uplink_name = key_uplink_name(&flow).await;
                        metrics::record_tun_tcp_event(&uplink_name, event);
                        metrics::record_tun_packet("upstream_to_tun", ip_family, packet_metric);
                    }
                    Ok(FlowMaintenancePlan::Wait(deadline)) => match deadline {
                        Some(deadline) if deadline <= Instant::now() => continue,
                        Some(deadline) => {
                            tokio::select! {
                                changed = close_rx.changed() => {
                                    if changed.is_err() || *close_rx.borrow() {
                                        return;
                                    }
                                }
                                _ = maintenance_notify.notified() => {}
                                _ = sleep_until(tokio::time::Instant::from_std(deadline)) => {}
                            }
                        }
                        None => {
                            tokio::select! {
                                changed = close_rx.changed() => {
                                    if changed.is_err() || *close_rx.borrow() {
                                        return;
                                    }
                                }
                                _ = maintenance_notify.notified() => {}
                            }
                        }
                    },
                    Err(error) => {
                        warn!(
                            error = %format!("{error:#}"),
                            "failed to plan TUN TCP flow maintenance"
                        );
                        engine
                            .abort_flow_with_rst(&key, "retransmit_build_error")
                            .await;
                        return;
                    }
                }
            }
        });
    }

    fn spawn_upstream_connect(
        &self,
        key: TcpFlowKey,
        target: TargetAddr,
        flow_id: u64,
        flow: Arc<Mutex<TcpFlowState>>,
        mut close_rx: watch::Receiver<bool>,
        ip_family: &'static str,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            struct AsyncConnectActiveGuard;
            impl Drop for AsyncConnectActiveGuard {
                fn drop(&mut self) {
                    metrics::add_tun_tcp_async_connects_active(-1);
                }
            }

            metrics::add_tun_tcp_async_connects_active(1);
            metrics::record_tun_tcp_async_connect("started");
            let _active_guard = AsyncConnectActiveGuard;

            let connected = tokio::select! {
                _ = close_rx.changed() => {
                    if *close_rx.borrow() {
                        metrics::record_tun_tcp_async_connect("cancelled");
                        debug!(flow_id, remote = %target, "cancelled pending async TUN TCP upstream connect");
                        return;
                    }
                    metrics::record_tun_tcp_async_connect("cancelled");
                    return;
                }
                result = timeout(
                    engine.inner.tcp.connect_timeout,
                    select_tcp_candidate_and_connect(&engine.inner.uplinks, &target),
                ) => result,
            };

            let (candidate, upstream_writer, upstream_reader) = match connected {
                Ok(Ok(connected)) => connected,
                Ok(Err(error)) => {
                    metrics::record_tun_tcp_async_connect("failed");
                    warn!(flow_id, remote = %target, error = %format!("{error:#}"), "failed to establish async TUN TCP upstream");
                    engine.abort_flow_with_rst(&key, "connect_failed").await;
                    return;
                }
                Err(_) => {
                    metrics::record_tun_tcp_async_connect("timeout");
                    warn!(flow_id, remote = %target, timeout_secs = engine.inner.tcp.connect_timeout.as_secs(), "timed out establishing async TUN TCP upstream");
                    engine.abort_flow_with_rst(&key, "connect_timeout").await;
                    return;
                }
            };

            let upstream_writer = Arc::new(Mutex::new(upstream_writer));
            let (pending_payloads, should_close_client_half) = {
                let mut state = flow.lock().await;
                if matches!(state.status, TcpFlowStatus::Closed) {
                    metrics::record_tun_tcp_async_connect("discarded_closed_flow");
                    drop(state);
                    close_upstream_writer(Some(Arc::clone(&upstream_writer))).await;
                    return;
                }
                clear_flow_metrics(&mut state);
                state.uplink_index = candidate.index;
                state.uplink_name = candidate.uplink.name.clone();
                state.upstream_writer = Some(Arc::clone(&upstream_writer));
                let pending_payloads = state.pending_client_data.drain(..).collect::<Vec<_>>();
                let should_close_client_half = client_fin_seen(state.status);
                sync_flow_metrics_and_wake(&mut state);
                (pending_payloads, should_close_client_half)
            };
            metrics::record_tun_tcp_async_connect("connected");

            engine.spawn_upstream_reader(
                key.clone(),
                flow.clone(),
                upstream_reader,
                close_rx.clone(),
            );

            for payload in pending_payloads {
                let send_result = {
                    let mut writer = upstream_writer.lock().await;
                    writer.send_chunk(&payload).await
                };
                if let Err(error) = send_result {
                    engine
                        .report_tcp_runtime_failure_and_abort(
                            &key,
                            candidate.index,
                            &error,
                            "send_error",
                        )
                        .await;
                    return;
                }
                metrics::add_bytes(
                    "tcp",
                    "client_to_upstream",
                    &candidate.uplink.name,
                    payload.len(),
                );
                engine
                    .inner
                    .uplinks
                    .report_active_traffic(candidate.index, TransportKind::Tcp, false)
                    .await;
            }

            if should_close_client_half {
                close_upstream_writer(Some(Arc::clone(&upstream_writer))).await;
            }

            metrics::record_uplink_selected("tcp", &candidate.uplink.name);
            info!(
                flow_id,
                uplink = %candidate.uplink.name,
                remote = %target,
                ip_family,
                "created TUN TCP flow"
            );
        });
    }

    async fn handle_existing_flow(
        &self,
        flow: Arc<Mutex<TcpFlowState>>,
        packet: ParsedTcpPacket,
    ) -> Result<()> {
        if self
            .inner
            .uplinks
            .strict_active_uplink_for(TransportKind::Tcp)
        {
            let active_uplink = self
                .inner
                .uplinks
                .active_uplink_index_for_transport(TransportKind::Tcp)
                .await;
            let (should_abort, key) = {
                let state = flow.lock().await;
                (
                    active_uplink.is_some_and(|active| {
                        state.uplink_index != usize::MAX && state.uplink_index != active
                    }),
                    state.key.clone(),
                )
            };
            if should_abort {
                self.abort_flow_with_rst(&key, "global_switch").await;
                return Ok(());
            }
        }

        let ip_family = ip_family_from_version(packet.version);
        let mut state = flow.lock().await;

        if state.status == TcpFlowStatus::SynReceived {
            if is_duplicate_syn(&packet, state.client_next_seq) {
                metrics::record_tun_tcp_event(&state.uplink_name, "duplicate_syn");
                let syn_ack = build_flow_syn_ack_packet(
                    &state,
                    state.server_seq.wrapping_sub(1),
                    state.client_next_seq,
                )?;
                let key = state.key.clone();
                drop(state);
                self.write_tun_packet_or_close_flow(&key, &syn_ack).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_synack");
                return Ok(());
            }
        }

        match validate_existing_packet(&state, &packet) {
            PacketValidation::Accept => {}
            PacketValidation::Ignore => return Ok(()),
            PacketValidation::CloseFlow(reason) => {
                let key = state.key.clone();
                drop(state);
                self.close_flow(&key, reason).await;
                if reason == "client_rst" {
                    metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_rst_observed");
                }
                return Ok(());
            }
            PacketValidation::ChallengeAck(event) => {
                let key = state.key.clone();
                let uplink_name = state.uplink_name.clone();
                let ack = build_flow_ack_packet(
                    &state,
                    state.server_seq,
                    state.client_next_seq,
                    TCP_FLAG_ACK,
                )?;
                drop(state);
                self.write_ack_packet_with_event(&key, ack, ip_family, &uplink_name, event)
                    .await?;
                return Ok(());
            }
        }

        note_recent_client_timestamp(&mut state, packet.timestamp_value);
        state.last_seen = Instant::now();
        update_client_send_window(&mut state, &packet);
        if state.client_window > 0 {
            reset_zero_window_persist(&mut state);
        }
        sync_flow_metrics_and_wake(&mut state);

        if state.status == TcpFlowStatus::SynReceived {
            if (packet.flags & TCP_FLAG_ACK) != 0
                && packet.acknowledgement_number == state.server_seq
                && packet.sequence_number == state.client_next_seq
            {
                set_flow_status(&mut state, TcpFlowStatus::Established);
                sync_flow_metrics_and_wake(&mut state);
            } else {
                let syn_ack = build_flow_syn_ack_packet(
                    &state,
                    state.server_seq.wrapping_sub(1),
                    state.client_next_seq,
                )?;
                let key = state.key.clone();
                drop(state);
                self.write_tun_packet_or_close_flow(&key, &syn_ack).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_synack");
                return Ok(());
            }
        }

        let ack_effect = process_server_ack(
            &mut state,
            packet.acknowledgement_number,
            &packet.sack_blocks,
        );
        let bytes_acked = ack_effect.bytes_acked;
        let rtt_sample = ack_effect.rtt_sample;
        if ack_effect.has_ack_progress() {
            note_ack_progress(
                &mut state,
                bytes_acked,
                rtt_sample,
                ack_effect.grow_congestion_window,
            );
            sync_flow_metrics_and_wake(&mut state);
        }

        if (packet.flags & TCP_FLAG_ACK) != 0
            && server_fin_awaiting_ack(state.status)
            && packet.acknowledgement_number >= state.server_seq
        {
            if transition_on_server_fin_ack(&mut state) {
                let key = state.key.clone();
                drop(state);
                self.close_flow(&key, "last_ack_acked").await;
                return Ok(());
            }
            sync_flow_metrics_and_wake(&mut state);
        }

        if ack_effect.retransmit_now {
            metrics::record_tun_tcp_event(&state.uplink_name, "fast_retransmit");
            if let Some(packet) = retransmit_oldest_unacked_packet(&mut state)? {
                if retransmit_budget_exhausted(&state, &self.inner.tcp) {
                    let key = state.key.clone();
                    drop(state);
                    self.abort_flow_with_rst(&key, "retransmit_budget_exhausted")
                        .await;
                    return Ok(());
                }
                sync_flow_metrics_and_wake(&mut state);
                let key = state.key.clone();
                drop(state);
                self.write_tun_packet_or_close_flow(&key, &packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_retransmit");
                return Ok(());
            }
        }

        if server_fin_awaiting_ack(state.status)
            && (packet.flags & TCP_FLAG_ACK) != 0
            && seq_lt(packet.acknowledgement_number, state.server_seq)
        {
            let fin_ack = build_flow_packet(
                &state,
                state.server_seq.wrapping_sub(1),
                state.client_next_seq,
                TCP_FLAG_FIN | TCP_FLAG_ACK,
                &[],
            )?;
            let key = state.key.clone();
            drop(state);
            self.write_tun_packet_or_close_flow(&key, &fin_ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_fin");
            return Ok(());
        }

        if client_fin_seen(state.status)
            && (!packet.payload.is_empty()
                || (packet.flags & TCP_FLAG_FIN) != 0
                || seq_lt(packet.sequence_number, state.client_next_seq))
        {
            let ack = build_flow_ack_packet(
                &state,
                state.server_seq,
                state.client_next_seq,
                TCP_FLAG_ACK,
            )?;
            let key = state.key.clone();
            drop(state);
            self.write_tun_packet_or_close_flow(&key, &ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
            return Ok(());
        }

        if seq_gt(packet.sequence_number, state.client_next_seq) {
            queue_future_segment_with_recv_window(&mut state, &packet);
            if exceeds_client_reassembly_limits(&state, &self.inner.tcp) {
                let key = state.key.clone();
                drop(state);
                self.abort_flow_with_rst(&key, "client_reassembly_limit")
                    .await;
                return Ok(());
            }
            sync_flow_metrics_and_wake(&mut state);
            let ack = build_flow_ack_packet(
                &state,
                state.server_seq,
                state.client_next_seq,
                TCP_FLAG_ACK,
            )?;
            let key = state.key.clone();
            drop(state);
            self.write_tun_packet_or_close_flow(&key, &ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
            return Ok(());
        }

        let Some(packet) = trim_packet_to_receive_window(&state, &packet) else {
            let ack = build_flow_ack_packet(
                &state,
                state.server_seq,
                state.client_next_seq,
                TCP_FLAG_ACK,
            )?;
            let key = state.key.clone();
            drop(state);
            self.write_tun_packet_or_close_flow(&key, &ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
            return Ok(());
        };

        let segment = normalize_client_segment(&packet, state.client_next_seq);
        let mut pending_payload = Vec::new();
        let mut should_close_client_half = false;
        let mut should_send_ack = false;
        let mut ack_number = state.client_next_seq;
        let seq_number = state.server_seq;
        let key = state.key.clone();
        let uplink_index = state.uplink_index;
        let uplink_name = state.uplink_name.clone();
        let upstream_writer = state.upstream_writer.clone();
        if !packet.payload.is_empty()
            || (packet.flags & TCP_FLAG_FIN) != 0
            || seq_lt(packet.sequence_number, state.client_next_seq)
        {
            should_send_ack = true;
        }
        if !segment.payload.is_empty() || segment.fin {
            apply_client_segment(
                &mut state.client_next_seq,
                segment,
                &mut pending_payload,
                &mut should_close_client_half,
            );
            if !should_close_client_half {
                should_close_client_half =
                    drain_ready_buffered_segments_from_state(&mut state, &mut pending_payload);
            }
            ack_number = state.client_next_seq;
            sync_flow_metrics_and_wake(&mut state);
        } else if (packet.flags & TCP_FLAG_ACK) != 0 && packet.payload.is_empty() {
            let flush = flush_server_output(&mut state)?;
            sync_flow_metrics_and_wake(&mut state);
            drop(state);
            if flush.window_stalled {
                metrics::record_tun_tcp_event(&key_uplink_name(&flow).await, "window_stall");
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_stall");
            }
            for packet in flush.data_packets {
                self.write_tun_packet_or_close_flow(&key, &packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_data");
            }
            if let Some(packet) = flush.probe_packet {
                self.write_tun_packet_or_close_flow(&key, &packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_probe");
            }
            if let Some(packet) = flush.fin_packet {
                self.write_tun_packet_or_close_flow(&key, &packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_fin");
            }
            return Ok(());
        }

        let flush = flush_server_output(&mut state)?;
        sync_flow_metrics_and_wake(&mut state);

        drop(state);

        if !pending_payload.is_empty() {
            if let Some(upstream_writer) = upstream_writer.clone() {
                let send_result = {
                    let mut upstream_writer = upstream_writer.lock().await;
                    upstream_writer.send_chunk(&pending_payload).await
                };
                if let Err(error) = send_result {
                    self.report_tcp_runtime_failure_and_abort(
                        &key,
                        uplink_index,
                        &error,
                        "send_error",
                    )
                    .await;
                    return Ok(());
                }
                metrics::add_bytes(
                    "tcp",
                    "client_to_upstream",
                    &uplink_name,
                    pending_payload.len(),
                );
                self.inner
                    .uplinks
                    .report_active_traffic(uplink_index, TransportKind::Tcp, false)
                    .await;
            } else if let Some(flow) = self.lookup_flow(&key).await {
                let mut state = flow.lock().await;
                state
                    .pending_client_data
                    .push_back(std::mem::take(&mut pending_payload).into());
                sync_flow_metrics_and_wake(&mut state);
            }
            should_send_ack = true;
        }

        if should_send_ack {
            let ack = {
                let state = flow.lock().await;
                build_flow_ack_packet(&state, seq_number, ack_number, TCP_FLAG_ACK)?
            };
            self.write_tun_packet_or_close_flow(&key, &ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
        }

        if flush.window_stalled {
            metrics::record_tun_tcp_event(&key_uplink_name(&flow).await, "window_stall");
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_stall");
        }
        for packet in flush.data_packets {
            self.write_tun_packet_or_close_flow(&key, &packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_data");
        }
        if let Some(packet) = flush.probe_packet {
            metrics::record_tun_tcp_event(&key_uplink_name(&flow).await, "zero_window_probe");
            self.write_tun_packet_or_close_flow(&key, &packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_probe");
        }
        if let Some(packet) = flush.fin_packet {
            metrics::record_tun_tcp_event(&key_uplink_name(&flow).await, "deferred_fin_sent");
            self.write_tun_packet_or_close_flow(&key, &packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_fin");
        }

        if should_close_client_half {
            {
                let mut state = flow.lock().await;
                transition_on_client_fin(&mut state);
                sync_flow_metrics_and_wake(&mut state);
            }
            close_upstream_writer(upstream_writer).await;
        }

        Ok(())
    }

    fn spawn_upstream_reader(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        mut upstream_reader: TcpShadowsocksReader,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                if engine
                    .inner
                    .uplinks
                    .strict_active_uplink_for(TransportKind::Tcp)
                {
                    let active_uplink = engine
                        .inner
                        .uplinks
                        .active_uplink_index_for_transport(TransportKind::Tcp)
                        .await;
                    let should_abort = {
                        let state = flow.lock().await;
                        active_uplink.is_some_and(|active| {
                            state.uplink_index != usize::MAX && state.uplink_index != active
                        })
                    };
                    if should_abort {
                        engine.abort_flow_with_rst(&key, "global_switch").await;
                        return;
                    }
                }

                let read_result = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            debug!("upstream TCP flow reader cancelled");
                            return;
                        }
                        continue;
                    }
                    result = upstream_reader.read_chunk() => result,
                };
                match read_result {
                    Ok(chunk) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        let chunk_len = chunk.len();
                        let uplink_index = {
                            let state = flow.lock().await;
                            state.uplink_index
                        };
                        engine
                            .inner
                            .uplinks
                            .report_active_traffic(uplink_index, TransportKind::Tcp, true)
                            .await;
                        let (flush, ip_family, backlog_pressure, uplink_name) = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.last_seen = Instant::now();
                            state.pending_server_data.push_back(chunk.into());
                            let flush = flush_server_output(&mut state);
                            let backlog_pressure = assess_server_backlog_pressure(
                                &mut state,
                                &engine.inner.tcp,
                                Instant::now(),
                                flush
                                    .as_ref()
                                    .map(|flush| flush.window_stalled)
                                    .unwrap_or(false),
                            );
                            sync_flow_metrics_and_wake(&mut state);
                            (
                                flush,
                                ip_family_from_version(key.version),
                                backlog_pressure,
                                state.uplink_name.clone(),
                            )
                        };

                        if backlog_pressure.should_abort {
                            let uplink_name = key_uplink_name(&flow).await;
                            let uplink_index = {
                                let state = flow.lock().await;
                                state.uplink_index
                            };
                            let error = anyhow!("server backlog limit exceeded for TUN TCP flow");
                            engine
                                .report_tcp_runtime_failure(uplink_index, &error)
                                .await;
                            let (cooldown_ms, penalty_ms) = engine
                                .inner
                                .uplinks
                                .runtime_failure_debug_state(uplink_index, TransportKind::Tcp)
                                .await;
                            warn!(
                                uplink = %uplink_name,
                                uplink_index,
                                cooldown_ms,
                                penalty_ms,
                                pending_bytes = backlog_pressure.pending_bytes,
                                limit_bytes = engine.inner.tcp.max_pending_server_bytes,
                                grace_ms = backlog_pressure.over_limit_ms.unwrap_or_default(),
                                no_progress_ms = backlog_pressure.no_progress_ms.unwrap_or_default(),
                                "closing TUN TCP flow after server backlog limit"
                            );
                            engine
                                .abort_flow_with_rst(&key, "server_backlog_limit")
                                .await;
                            return;
                        } else if backlog_pressure.exceeded {
                            debug!(
                                uplink = %uplink_name,
                                pending_bytes = backlog_pressure.pending_bytes,
                                limit_bytes = engine.inner.tcp.max_pending_server_bytes,
                                over_limit_ms = backlog_pressure.over_limit_ms.unwrap_or_default(),
                                no_progress_ms = backlog_pressure.no_progress_ms.unwrap_or_default(),
                                window_stalled = backlog_pressure.window_stalled,
                                "TUN TCP flow is under backlog pressure, delaying abort"
                            );
                        }

                        match flush {
                            Ok(flush) => {
                                if flush.window_stalled {
                                    let uplink_name = key_uplink_name(&flow).await;
                                    metrics::record_tun_tcp_event(&uplink_name, "window_stall");
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_window_stall",
                                    );
                                }
                                for packet in flush.data_packets {
                                    if let Err(error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{error:#}"), "failed to write TUN TCP data packet");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_data",
                                    );
                                }
                                if let Some(packet) = flush.probe_packet {
                                    let uplink_name = key_uplink_name(&flow).await;
                                    metrics::record_tun_tcp_event(
                                        &uplink_name,
                                        "zero_window_probe",
                                    );
                                    if let Err(error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{error:#}"), "failed to write TUN TCP zero-window probe");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_window_probe",
                                    );
                                }
                                if let Some(packet) = flush.fin_packet {
                                    let uplink_name = key_uplink_name(&flow).await;
                                    metrics::record_tun_tcp_event(
                                        &uplink_name,
                                        "deferred_fin_sent",
                                    );
                                    if let Err(error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{error:#}"), "failed to write deferred TUN TCP FIN packet");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_fin",
                                    );
                                }
                                metrics::add_bytes(
                                    "tcp",
                                    "upstream_to_client",
                                    &uplink_name,
                                    chunk_len,
                                );
                            }
                            Err(error) => {
                                warn!(error = %format!("{error:#}"), "failed to build TUN TCP data packet");
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        // Transport errors (e.g. QUIC APPLICATION_CLOSE /
                        // H3_INTERNAL_ERROR) set closed_cleanly=false.  Report
                        // them as uplink runtime failures so the penalty system
                        // can switch to a backup uplink or fall back to H2/H1.
                        // Clean WebSocket closes (FIN, Close frame) do not
                        // indicate an uplink problem and are not reported.
                        let uplink_index = flow.lock().await.uplink_index;
                        if !upstream_reader.closed_cleanly {
                            engine
                                .report_tcp_runtime_failure(uplink_index, &error)
                                .await;
                        } else {
                            engine
                                .inner
                                .uplinks
                                .report_upstream_close(uplink_index, TransportKind::Tcp)
                                .await;
                        }
                        debug!(error = %format!("{error:#}"), "upstream TCP flow reader ended");
                        let flush = {
                            let mut state = flow.lock().await;
                            if state.status == TcpFlowStatus::Closed
                                || server_fin_sent(state.status)
                            {
                                Ok(ServerFlush::default())
                            } else {
                                state.server_fin_pending = true;
                                let flush = flush_server_output(&mut state);
                                sync_flow_metrics_and_wake(&mut state);
                                flush
                            }
                        };

                        match flush {
                            Ok(flush) => {
                                let uplink_name = key_uplink_name(&flow).await;
                                let ip_family = ip_family_from_version(key.version);
                                if flush.window_stalled {
                                    metrics::record_tun_tcp_event(&uplink_name, "window_stall");
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_window_stall",
                                    );
                                }
                                for packet in flush.data_packets {
                                    if let Err(write_error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{write_error:#}"), "failed to write pending TUN TCP data packet");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_data",
                                    );
                                }
                                if let Some(packet) = flush.probe_packet {
                                    metrics::record_tun_tcp_event(
                                        &uplink_name,
                                        "zero_window_probe",
                                    );
                                    if let Err(write_error) =
                                        engine.inner.writer.write_packet(&packet).await
                                    {
                                        warn!(error = %format!("{write_error:#}"), "failed to write TUN TCP zero-window probe");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_window_probe",
                                    );
                                }
                                if let Some(fin) = flush.fin_packet {
                                    metrics::record_tun_tcp_event(
                                        &uplink_name,
                                        "deferred_fin_sent",
                                    );
                                    if let Err(write_error) =
                                        engine.inner.writer.write_packet(&fin).await
                                    {
                                        warn!(error = %format!("{write_error:#}"), "failed to write TUN TCP FIN packet");
                                        engine.close_flow(&key, "write_tun_error").await;
                                        return;
                                    }
                                    metrics::record_tun_packet(
                                        "upstream_to_tun",
                                        ip_family,
                                        "tcp_fin",
                                    );
                                }
                            }
                            Err(flush_error) => {
                                warn!(error = %format!("{flush_error:#}"), "failed to flush deferred server FIN/data");
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            }
                        }

                        let should_close = {
                            let state = flow.lock().await;
                            state.status == TcpFlowStatus::Closed
                        };
                        if should_close {
                            engine.close_flow(&key, "upstream_closed").await;
                        }
                        return;
                    }
                }
            }
        });
    }

    async fn close_flow(&self, key: &TcpFlowKey, reason: &'static str) {
        let flow = self.inner.flows.write().await.remove(key);
        if let Some(flow) = flow {
            let (flow_id, uplink_name, _duration, upstream_writer, close_signal) = {
                let mut state = flow.lock().await;
                set_flow_status(&mut state, TcpFlowStatus::Closed);
                clear_flow_metrics(&mut state);
                (
                    state.id,
                    state.uplink_name.clone(),
                    state.created_at.elapsed(),
                    state.upstream_writer.clone(),
                    state.close_signal.clone(),
                )
            };
            let _ = close_signal.send(true);
            close_upstream_writer(upstream_writer).await;
            metrics::record_tun_tcp_event(&uplink_name, reason);
            debug!(flow_id, uplink = %uplink_name, reason, "closed TUN TCP flow");
            self.maybe_shrink_flow_table().await;
        }
    }

    async fn oldest_flow_key(&self) -> Option<TcpFlowKey> {
        let flows = {
            let guard = self.inner.flows.read().await;
            guard
                .iter()
                .map(|(key, flow)| (key.clone(), Arc::clone(flow)))
                .collect::<Vec<_>>()
        };
        let mut oldest = None;
        for (key, flow) in flows {
            let last_seen = flow.lock().await.last_seen;
            if oldest
                .as_ref()
                .map(|(_, best_last_seen)| last_seen < *best_last_seen)
                .unwrap_or(true)
            {
                oldest = Some((key, last_seen));
            }
        }
        oldest.map(|(key, _)| key)
    }

    async fn maybe_shrink_flow_table(&self) {
        let mut guard = self.inner.flows.write().await;
        maybe_shrink_hash_map(&mut guard);
    }
}
