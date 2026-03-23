use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use tokio::sync::{Mutex, Notify, watch};
use tokio::time::{sleep_until, timeout};
use tracing::{debug, info, warn};

use crate::config::TunTcpConfig;
use crate::memory::maybe_shrink_hash_map;
use crate::metrics;
use crate::transport::{
    TcpShadowsocksReader, TcpShadowsocksWriter, UpstreamTransportGuard,
    connect_shadowsocks_tcp_with_source,
};
use crate::tun::SharedTunWriter;
use crate::types::{TargetAddr, UplinkTransport};
use crate::uplink::{TransportKind, UplinkCandidate, UplinkManager};

pub(crate) const IPV4_HEADER_LEN: usize = 20;
pub(crate) const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
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
const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
const IPV6_NEXT_HEADER_TCP: u8 = 6;
const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_NEXT_HEADER_AUTH: u8 = 51;
const IPV6_NEXT_HEADER_DESTINATION_OPTIONS: u8 = 60;
const IPV6_NEXT_HEADER_NONE: u8 = 59;

mod state_machine;

#[cfg(test)]
use self::state_machine::{
    BufferedClientSegment, ClientSegmentView, ServerSegment, drain_ready_buffered_segments,
    queue_future_segment,
};
use self::state_machine::{
    ServerFlush, TcpFlowState, TcpFlowStatus, apply_client_segment, assess_server_backlog_pressure,
    build_flow_ack_packet, build_flow_packet, build_flow_syn_ack_packet, clear_flow_metrics,
    client_fin_seen, decode_client_window, drain_ready_buffered_segments_from_state,
    exceeds_client_reassembly_limits, flush_server_output, is_duplicate_syn,
    maybe_emit_zero_window_probe, next_retransmission_deadline, normalize_client_segment,
    note_ack_progress, note_congestion_event, note_recent_client_timestamp,
    packet_overlaps_receive_window, process_server_ack, queue_future_segment_with_recv_window,
    reset_zero_window_persist, retransmit_budget_exhausted, retransmit_due_segment,
    retransmit_oldest_unacked_packet, seq_gt, seq_lt, server_fin_awaiting_ack, server_fin_sent,
    set_flow_status, sync_flow_metrics, timestamp_lt, transition_on_client_fin,
    transition_on_server_fin_ack, trim_packet_to_receive_window, update_client_send_window,
};

#[derive(Clone)]
pub struct TunTcpEngine {
    inner: Arc<TunTcpEngineInner>,
}

struct TunTcpEngineInner {
    writer: SharedTunWriter,
    uplinks: UplinkManager,
    flows: Mutex<HashMap<TcpFlowKey, Arc<Mutex<TcpFlowState>>>>,
    pending_connects: Mutex<HashSet<TcpFlowKey>>,
    next_flow_id: AtomicU64,
    max_flows: usize,
    idle_timeout: Duration,
    tcp: TunTcpConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    version: IpVersion,
    client_ip: IpAddr,
    client_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Debug, Clone)]
struct ParsedTcpPacket {
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    window_size: u16,
    max_segment_size: Option<u16>,
    window_scale: Option<u8>,
    sack_permitted: bool,
    sack_blocks: Vec<(u32, u32)>,
    timestamp_value: Option<u32>,
    #[cfg_attr(not(test), allow(dead_code))]
    timestamp_echo_reply: Option<u32>,
    flags: u8,
    payload: Vec<u8>,
}

#[derive(Debug, Default)]
struct ParsedTcpOptions {
    max_segment_size: Option<u16>,
    window_scale: Option<u8>,
    sack_permitted: bool,
    sack_blocks: Vec<(u32, u32)>,
    timestamp_value: Option<u32>,
    timestamp_echo_reply: Option<u32>,
}

enum PacketValidation {
    Accept,
    Ignore,
    ChallengeAck(&'static str),
    CloseFlow(&'static str),
}

enum FlowMaintenancePlan {
    Wait(Option<Instant>),
    SendPacket {
        packet: Vec<u8>,
        packet_metric: &'static str,
        event: &'static str,
    },
    Abort(&'static str),
    Close(&'static str),
}

fn sync_flow_metrics_and_wake(state: &mut TcpFlowState) {
    sync_flow_metrics(state);
    state.maintenance_notify.notify_one();
}

fn next_zero_window_probe_deadline(state: &TcpFlowState) -> Option<Instant> {
    if state.client_window == 0
        && !state.pending_server_data.is_empty()
        && state.unacked_server_segments.is_empty()
    {
        Some(state.next_zero_window_probe_at.unwrap_or_else(Instant::now))
    } else {
        None
    }
}

fn next_flow_deadline(
    state: &TcpFlowState,
    tcp: &TunTcpConfig,
    idle_timeout: Duration,
) -> Option<Instant> {
    let mut deadline = next_retransmission_deadline(state)
        .into_iter()
        .chain(next_zero_window_probe_deadline(state))
        .min();

    if state.status == TcpFlowStatus::SynReceived {
        deadline = Some(
            deadline
                .map(|current| current.min(state.status_since + tcp.handshake_timeout))
                .unwrap_or(state.status_since + tcp.handshake_timeout),
        );
    }

    if matches!(
        state.status,
        TcpFlowStatus::CloseWait
            | TcpFlowStatus::FinWait1
            | TcpFlowStatus::FinWait2
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck
    ) {
        deadline = Some(
            deadline
                .map(|current| current.min(state.status_since + tcp.half_close_timeout))
                .unwrap_or(state.status_since + tcp.half_close_timeout),
        );
    }

    if state.status == TcpFlowStatus::TimeWait {
        deadline = Some(
            deadline
                .map(|current| current.min(state.status_since + TCP_TIME_WAIT_TIMEOUT))
                .unwrap_or(state.status_since + TCP_TIME_WAIT_TIMEOUT),
        );
    } else {
        deadline = Some(
            deadline
                .map(|current| current.min(state.last_seen + idle_timeout))
                .unwrap_or(state.last_seen + idle_timeout),
        );
    }

    deadline
}

fn plan_flow_maintenance(
    state: &mut TcpFlowState,
    tcp: &TunTcpConfig,
    idle_timeout: Duration,
    now: Instant,
) -> Result<FlowMaintenancePlan> {
    if state.status == TcpFlowStatus::TimeWait
        && now.saturating_duration_since(state.status_since) >= TCP_TIME_WAIT_TIMEOUT
    {
        return Ok(FlowMaintenancePlan::Close("time_wait_expired"));
    }

    if state.status == TcpFlowStatus::SynReceived
        && now.saturating_duration_since(state.status_since) >= tcp.handshake_timeout
    {
        return Ok(FlowMaintenancePlan::Abort("handshake_timeout"));
    }

    if matches!(
        state.status,
        TcpFlowStatus::CloseWait
            | TcpFlowStatus::FinWait1
            | TcpFlowStatus::FinWait2
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck
    ) && now.saturating_duration_since(state.status_since) >= tcp.half_close_timeout
    {
        return Ok(FlowMaintenancePlan::Abort("half_close_timeout"));
    }

    if state.status != TcpFlowStatus::TimeWait
        && now.saturating_duration_since(state.last_seen) >= idle_timeout
    {
        return Ok(FlowMaintenancePlan::Abort("idle_timeout"));
    }

    if let Some(packet) = retransmit_due_segment(state)? {
        note_congestion_event(state, true);
        if retransmit_budget_exhausted(state, tcp) {
            return Ok(FlowMaintenancePlan::Abort("retransmit_budget_exhausted"));
        }
        sync_flow_metrics_and_wake(state);
        return Ok(FlowMaintenancePlan::SendPacket {
            packet,
            packet_metric: "tcp_retransmit",
            event: "timeout_retransmit",
        });
    }

    if let Some(packet) = maybe_emit_zero_window_probe(state)? {
        sync_flow_metrics_and_wake(state);
        return Ok(FlowMaintenancePlan::SendPacket {
            packet,
            packet_metric: "tcp_window_probe",
            event: "zero_window_probe",
        });
    }

    Ok(FlowMaintenancePlan::Wait(next_flow_deadline(
        state,
        tcp,
        idle_timeout,
    )))
}

fn validate_packet_timestamps(state: &TcpFlowState, packet: &ParsedTcpPacket) -> PacketValidation {
    if !state.timestamps_enabled || (packet.flags & TCP_FLAG_RST) != 0 {
        return PacketValidation::Accept;
    }

    let Some(timestamp_value) = packet.timestamp_value else {
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("missing_timestamp")
        } else {
            PacketValidation::Ignore
        };
    };

    if state
        .recent_client_timestamp
        .is_some_and(|recent| timestamp_lt(timestamp_value, recent))
    {
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("paws_reject")
        } else {
            PacketValidation::Ignore
        };
    }

    PacketValidation::Accept
}

fn validate_existing_packet(state: &TcpFlowState, packet: &ParsedTcpPacket) -> PacketValidation {
    if (packet.flags & TCP_FLAG_RST) != 0 {
        if packet.sequence_number == state.client_next_seq {
            return PacketValidation::CloseFlow("client_rst");
        }
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("invalid_rst")
        } else {
            PacketValidation::Ignore
        };
    }

    match validate_packet_timestamps(state, packet) {
        PacketValidation::Accept => {}
        other => return other,
    }

    if (packet.flags & TCP_FLAG_SYN) != 0 {
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("unexpected_syn")
        } else {
            PacketValidation::Ignore
        };
    }

    if (packet.flags & TCP_FLAG_ACK) != 0 && seq_gt(packet.acknowledgement_number, state.server_seq)
    {
        return if packet_overlaps_receive_window(state, packet) {
            PacketValidation::ChallengeAck("ack_above_snd_nxt")
        } else {
            PacketValidation::Ignore
        };
    }

    PacketValidation::Accept
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
                flows: Mutex::new(HashMap::new()),
                pending_connects: Mutex::new(HashSet::new()),
                next_flow_id: AtomicU64::new(1),
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
        self.inner.flows.lock().await.get(key).cloned()
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

    async fn abort_flow_with_rst(&self, key: &TcpFlowKey, reason: &'static str) {
        let flow = self.inner.flows.lock().await.remove(key);
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
        if self.inner.flows.lock().await.len() >= self.inner.max_flows {
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
            let mut guard = self.inner.flows.lock().await;
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
                        .inner
                        .uplinks
                        .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                        .await;
                    engine.abort_flow_with_rst(&key, "send_error").await;
                    return;
                }
                metrics::add_bytes(
                    "tcp",
                    "client_to_upstream",
                    &candidate.uplink.name,
                    payload.len(),
                );
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
                    self.inner
                        .uplinks
                        .report_runtime_failure(uplink_index, TransportKind::Tcp, &error)
                        .await;
                    self.abort_flow_with_rst(&key, "send_error").await;
                    return Ok(());
                }
                metrics::add_bytes(
                    "tcp",
                    "client_to_upstream",
                    &uplink_name,
                    pending_payload.len(),
                );
            } else if let Some(flow) = self.lookup_flow(&key).await {
                let mut state = flow.lock().await;
                state.pending_client_data.push_back(pending_payload.clone());
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
                        let (flush, ip_family, backlog_pressure, uplink_name) = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.last_seen = Instant::now();
                            state.pending_server_data.push_back(chunk.clone());
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
                                .inner
                                .uplinks
                                .report_runtime_failure(uplink_index, TransportKind::Tcp, &error)
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
                                    chunk.len(),
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
                        if !upstream_reader.closed_cleanly {
                            let uplink_index = flow.lock().await.uplink_index;
                            if uplink_index != usize::MAX {
                                engine
                                    .inner
                                    .uplinks
                                    .report_runtime_failure(
                                        uplink_index,
                                        TransportKind::Tcp,
                                        &error,
                                    )
                                    .await;
                            }
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
        let flow = self.inner.flows.lock().await.remove(key);
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
            let guard = self.inner.flows.lock().await;
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
        let mut guard = self.inner.flows.lock().await;
        maybe_shrink_hash_map(&mut guard);
    }
}

async fn close_upstream_writer(upstream_writer: Option<Arc<Mutex<TcpShadowsocksWriter>>>) {
    let Some(upstream_writer) = upstream_writer else {
        return;
    };
    let mut upstream_writer = upstream_writer.lock().await;
    let _ = upstream_writer.close().await;
}

async fn key_uplink_name(flow: &Arc<Mutex<TcpFlowState>>) -> String {
    flow.lock().await.uplink_name.clone()
}

async fn select_tcp_candidate_and_connect(
    uplinks: &UplinkManager,
    target: &TargetAddr,
) -> Result<(UplinkCandidate, TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let mut last_error = None;
    let mut failed_uplink = None::<String>;
    let strict_transport = uplinks.strict_active_uplink_for(TransportKind::Tcp);
    let mut tried_indexes = std::collections::HashSet::new();
    loop {
        let candidates = uplinks.tcp_candidates(target).await;
        if candidates.is_empty() {
            let cooldowns = uplinks.tcp_cooldown_debug_summary().await;
            warn!(
                remote = %target,
                tcp_uplinks = cooldowns.join("; "),
                "dropping TUN TCP flow because all TCP uplinks are in cooldown or unavailable"
            );
            return Err(anyhow!(
                "all TCP uplinks are in cooldown or unavailable for TUN flow"
            ));
        }

        let iter = if strict_transport {
            candidates.into_iter().take(1).collect::<Vec<_>>()
        } else {
            candidates
        };
        let mut progressed = false;
        for candidate in iter {
            if strict_transport && !tried_indexes.insert(candidate.index) {
                continue;
            }
            progressed = true;
            match connect_tcp_uplink(uplinks, &candidate, target).await {
                Ok((writer, reader)) => {
                    uplinks
                        .confirm_selected_uplink(TransportKind::Tcp, Some(target), candidate.index)
                        .await;
                    if let Some(from_uplink) = failed_uplink.take() {
                        metrics::record_failover("tcp", &from_uplink, &candidate.uplink.name);
                        info!(
                            from_uplink,
                            to_uplink = %candidate.uplink.name,
                            remote = %target,
                            "runtime TCP failover activated for TUN flow"
                        );
                    }
                    return Ok((candidate, writer, reader));
                }
                Err(error) => {
                    uplinks
                        .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                        .await;
                    if failed_uplink.is_none() {
                        failed_uplink = Some(candidate.uplink.name.clone());
                    }
                    last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
                }
            }
        }
        if !strict_transport || !progressed {
            break;
        }
    }

    Err(anyhow!(
        "all TCP uplinks failed for TUN flow: {}",
        last_error.unwrap_or_else(|| "no uplinks available".to_string())
    ))
}

async fn connect_tcp_uplink(
    uplinks: &UplinkManager,
    candidate: &UplinkCandidate,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    if candidate.uplink.transport == UplinkTransport::Shadowsocks {
        let stream = connect_shadowsocks_tcp_with_source(
            candidate
                .uplink
                .tcp_addr
                .as_ref()
                .ok_or_else(|| anyhow!("uplink {} missing tcp_addr", candidate.uplink.name))?,
            candidate.uplink.fwmark,
            candidate.uplink.ipv6_first,
            "tun_tcp",
        )
        .await?;
        return do_tcp_ss_setup_socket(stream, &candidate.uplink, target).await;
    }

    // Variant A: try a standby pool connection first.  If it turns out to be
    // stale (fails before any server bytes arrive), discard it silently and
    // retry with a fresh on-demand dial — without recording a runtime failure.
    if let Some(ws) = uplinks.try_take_tcp_standby(candidate).await {
        match do_tcp_ss_setup(ws, &candidate.uplink, target).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                debug!(
                    uplink = %candidate.uplink.name,
                    error = %format!("{e:#}"),
                    "stale standby TCP pool connection, retrying with fresh dial"
                );
            }
        }
    }

    let ws = uplinks.connect_tcp_ws_fresh(candidate, "tun_tcp").await?;
    do_tcp_ss_setup(ws, &candidate.uplink, target).await
}

async fn do_tcp_ss_setup(
    ws_stream: crate::transport::AnyWsStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let (ws_sink, ws_stream) = ws_stream.split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new("tun_tcp", "tcp");
    let (mut writer, ctrl_tx) =
        TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key, Arc::clone(&lifetime))
            .await?;
    let request_salt = writer.request_salt().map(|salt| salt.to_vec());
    let reader =
        TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key, lifetime, ctrl_tx)
            .with_request_salt(request_salt);
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((writer, reader))
}

async fn do_tcp_ss_setup_socket(
    stream: tokio::net::TcpStream,
    uplink: &crate::config::UplinkConfig,
    target: &TargetAddr,
) -> Result<(TcpShadowsocksWriter, TcpShadowsocksReader)> {
    let (reader_half, writer_half) = stream.into_split();
    let master_key = uplink.cipher.derive_master_key(&uplink.password)?;
    let lifetime = UpstreamTransportGuard::new("tun_tcp", "tcp");
    let mut writer = TcpShadowsocksWriter::connect_socket(
        writer_half,
        uplink.cipher,
        &master_key,
        Arc::clone(&lifetime),
    )?;
    let reader =
        TcpShadowsocksReader::new_socket(reader_half, uplink.cipher, &master_key, lifetime)
            .with_request_salt(writer.request_salt().map(|salt| salt.to_vec()));
    writer
        .send_chunk(&target.to_wire_bytes()?)
        .await
        .context("failed to send target address")?;
    Ok((writer, reader))
}

fn parse_tcp_packet(packet: &[u8]) -> Result<ParsedTcpPacket> {
    let version = packet
        .first()
        .ok_or_else(|| anyhow!("empty TUN TCP packet"))?
        >> 4;
    match version {
        4 => parse_ipv4_tcp_packet(packet),
        6 => parse_ipv6_tcp_packet(packet),
        other => bail!("unsupported IP version in TUN TCP packet: {other}"),
    }
}

fn parse_ipv4_tcp_packet(packet: &[u8]) -> Result<ParsedTcpPacket> {
    if packet.len() < IPV4_HEADER_LEN + TCP_HEADER_LEN {
        bail!("short IPv4 TCP packet");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < IPV4_HEADER_LEN || total_len < header_len + TCP_HEADER_LEN {
        bail!("invalid IPv4 packet lengths");
    }
    if packet.len() < total_len {
        bail!("truncated IPv4 TCP packet");
    }
    if checksum16(&packet[..header_len]) != 0 {
        bail!("invalid IPv4 header checksum");
    }
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (fragment_field & 0x1fff) != 0 || (fragment_field & 0x2000) != 0 {
        bail!("IPv4 fragments are not supported on TUN TCP path");
    }
    if packet[9] != IPV6_NEXT_HEADER_TCP {
        bail!("expected IPv4 TCP packet");
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    parse_tcp_segment(
        IpVersion::V4,
        IpAddr::V4(src),
        IpAddr::V4(dst),
        &packet[header_len..total_len],
    )
}

fn parse_ipv6_tcp_packet(packet: &[u8]) -> Result<ParsedTcpPacket> {
    if packet.len() < IPV6_HEADER_LEN + TCP_HEADER_LEN {
        bail!("short IPv6 TCP packet");
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if packet.len() < total_len {
        bail!("truncated IPv6 TCP packet");
    }
    let (next_header, segment_offset) = locate_ipv6_tcp_segment(packet, total_len)?;
    if next_header != IPV6_NEXT_HEADER_TCP {
        bail!("expected IPv6 TCP packet");
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    parse_tcp_segment(
        IpVersion::V6,
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        &packet[segment_offset..total_len],
    )
}

fn locate_ipv6_tcp_segment(packet: &[u8], total_len: usize) -> Result<(u8, usize)> {
    let mut next_header = packet[6];
    let mut offset = IPV6_HEADER_LEN;

    loop {
        match next_header {
            IPV6_NEXT_HEADER_TCP => return Ok((next_header, offset)),
            IPV6_NEXT_HEADER_HOP_BY_HOP
            | IPV6_NEXT_HEADER_ROUTING
            | IPV6_NEXT_HEADER_DESTINATION_OPTIONS => {
                if offset + 2 > total_len {
                    bail!("truncated IPv6 extension header");
                }
                let header_len = (usize::from(packet[offset + 1]) + 1) * 8;
                if header_len < 8 || offset + header_len > total_len {
                    bail!("invalid IPv6 extension header length");
                }
                next_header = packet[offset];
                offset += header_len;
            }
            IPV6_NEXT_HEADER_AUTH => {
                if offset + 2 > total_len {
                    bail!("truncated IPv6 authentication header");
                }
                let header_len = (usize::from(packet[offset + 1]) + 2) * 4;
                if header_len < 8 || offset + header_len > total_len {
                    bail!("invalid IPv6 authentication header length");
                }
                next_header = packet[offset];
                offset += header_len;
            }
            IPV6_NEXT_HEADER_FRAGMENT => {
                bail!("IPv6 fragments are not supported on TUN TCP path");
            }
            IPV6_NEXT_HEADER_NONE => {
                bail!("expected IPv6 TCP packet");
            }
            _ => {
                bail!("IPv6 extension headers are not supported on TUN TCP path");
            }
        }
    }
}

fn parse_tcp_segment(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    segment: &[u8],
) -> Result<ParsedTcpPacket> {
    if segment.len() < TCP_HEADER_LEN {
        bail!("short TCP segment");
    }
    validate_tcp_checksum(version, source_ip, destination_ip, segment)?;
    let header_len = usize::from(segment[12] >> 4) * 4;
    if header_len < TCP_HEADER_LEN || segment.len() < header_len {
        bail!("invalid TCP header length");
    }
    let options = parse_tcp_options(&segment[TCP_HEADER_LEN..header_len])?;

    Ok(ParsedTcpPacket {
        version,
        source_ip,
        destination_ip,
        source_port: u16::from_be_bytes([segment[0], segment[1]]),
        destination_port: u16::from_be_bytes([segment[2], segment[3]]),
        sequence_number: u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        acknowledgement_number: u32::from_be_bytes([
            segment[8],
            segment[9],
            segment[10],
            segment[11],
        ]),
        window_size: u16::from_be_bytes([segment[14], segment[15]]),
        max_segment_size: options.max_segment_size,
        window_scale: options.window_scale,
        sack_permitted: options.sack_permitted,
        sack_blocks: options.sack_blocks,
        timestamp_value: options.timestamp_value,
        timestamp_echo_reply: options.timestamp_echo_reply,
        flags: segment[13],
        payload: segment[header_len..].to_vec(),
    })
}

fn validate_tcp_checksum(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    segment: &[u8],
) -> Result<()> {
    let checksum_valid = match (version, source_ip, destination_ip) {
        (IpVersion::V4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            tcp_checksum_ipv4(source_ip, destination_ip, segment) == 0
        }
        (IpVersion::V6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            tcp_checksum_ipv6(source_ip, destination_ip, segment) == 0
        }
        _ => bail!("unexpected address family while validating TCP checksum"),
    };
    if !checksum_valid {
        bail!("invalid TCP checksum");
    }
    Ok(())
}

fn parse_tcp_options(options: &[u8]) -> Result<ParsedTcpOptions> {
    let mut parsed = ParsedTcpOptions::default();
    let mut index = 0usize;
    while index < options.len() {
        match options[index] {
            0 => break,
            1 => index += 1,
            kind => {
                if index + 1 >= options.len() {
                    bail!("truncated TCP option header");
                }
                let len = usize::from(options[index + 1]);
                if len < 2 || index + len > options.len() {
                    bail!("invalid TCP option length");
                }
                let body = &options[index + 2..index + len];
                match kind {
                    2 if body.len() == 2 => {
                        parsed.max_segment_size =
                            Some(u16::from_be_bytes([body[0], body[1]]).max(1));
                    }
                    3 if body.len() == 1 => {
                        parsed.window_scale = Some(body[0].min(14));
                    }
                    4 if body.is_empty() => {
                        parsed.sack_permitted = true;
                    }
                    5 if body.len() >= 8 && body.len() % 8 == 0 => {
                        for block in body.chunks_exact(8) {
                            let left = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
                            let right =
                                u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
                            if seq_lt(left, right) {
                                parsed.sack_blocks.push((left, right));
                            }
                        }
                    }
                    8 if body.len() == 8 => {
                        parsed.timestamp_value =
                            Some(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
                        parsed.timestamp_echo_reply =
                            Some(u32::from_be_bytes([body[4], body[5], body[6], body[7]]));
                    }
                    _ => {}
                }
                index += len;
            }
        }
    }
    Ok(parsed)
}

fn build_reset_response(packet: &ParsedTcpPacket) -> Result<Vec<u8>> {
    let response_seq = if (packet.flags & TCP_FLAG_ACK) != 0 {
        packet.acknowledgement_number
    } else {
        0
    };
    let response_ack = if (packet.flags & TCP_FLAG_ACK) != 0 {
        0
    } else {
        packet
            .sequence_number
            .wrapping_add(packet.payload.len() as u32)
            .wrapping_add(u32::from((packet.flags & TCP_FLAG_SYN) != 0))
            .wrapping_add(u32::from((packet.flags & TCP_FLAG_FIN) != 0))
    };
    let response_flags = if (packet.flags & TCP_FLAG_ACK) != 0 {
        TCP_FLAG_RST
    } else {
        TCP_FLAG_RST | TCP_FLAG_ACK
    };

    build_response_packet(
        packet.version,
        packet.destination_ip,
        packet.source_ip,
        packet.destination_port,
        packet.source_port,
        response_seq,
        response_ack,
        response_flags,
        &[],
    )
}

fn build_response_packet(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    build_response_packet_custom(
        version,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        0xffff,
        &[],
        payload,
    )
}

fn build_response_packet_custom(
    version: IpVersion,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    match (version, source_ip, destination_ip) {
        (IpVersion::V4, IpAddr::V4(source_ip), IpAddr::V4(destination_ip)) => {
            build_ipv4_tcp_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                flags,
                window_size,
                options,
                payload,
            )
        }
        (IpVersion::V6, IpAddr::V6(source_ip), IpAddr::V6(destination_ip)) => {
            build_ipv6_tcp_packet(
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                sequence_number,
                acknowledgement_number,
                flags,
                window_size,
                options,
                payload,
            )
        }
        _ => bail!("unexpected address family in TUN TCP response"),
    }
}

fn build_ipv4_tcp_packet(
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if options.len() % 4 != 0 {
        bail!("TCP options must be 32-bit aligned");
    }
    let tcp_header_len = TCP_HEADER_LEN + options.len();
    let total_len = IPV4_HEADER_LEN + tcp_header_len + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source_ip.octets());
    packet[16..20].copy_from_slice(&destination_ip.octets());

    let tcp = &mut packet[IPV4_HEADER_LEN..];
    build_tcp_segment(
        tcp,
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
        payload,
    );

    let tcp_checksum = tcp_checksum_ipv4(source_ip, destination_ip, tcp);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
    let header_checksum = checksum16(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(packet)
}

fn build_ipv6_tcp_packet(
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    if options.len() % 4 != 0 {
        bail!("TCP options must be 32-bit aligned");
    }
    let tcp_header_len = TCP_HEADER_LEN + options.len();
    let total_len = IPV6_HEADER_LEN + tcp_header_len + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((tcp_header_len + payload.len()) as u16).to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source_ip.octets());
    packet[24..40].copy_from_slice(&destination_ip.octets());

    let tcp = &mut packet[IPV6_HEADER_LEN..];
    build_tcp_segment(
        tcp,
        source_port,
        destination_port,
        sequence_number,
        acknowledgement_number,
        flags,
        window_size,
        options,
        payload,
    );

    let tcp_checksum = tcp_checksum_ipv6(source_ip, destination_ip, tcp);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(packet)
}

fn build_tcp_segment(
    tcp: &mut [u8],
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    window_size: u16,
    options: &[u8],
    payload: &[u8],
) {
    let header_len = TCP_HEADER_LEN + options.len();
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence_number.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement_number.to_be_bytes());
    tcp[12] = ((header_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&window_size.to_be_bytes());
    tcp[18..20].copy_from_slice(&0u16.to_be_bytes());
    if !options.is_empty() {
        tcp[TCP_HEADER_LEN..header_len].copy_from_slice(options);
    }
    tcp[header_len..header_len + payload.len()].copy_from_slice(payload);
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let value = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            u16::from_be_bytes([chunk[0], 0]) as u32
        };
        sum = sum.wrapping_add(value);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum_ipv4(source: Ipv4Addr, destination: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    checksum16(&pseudo)
}

fn tcp_checksum_ipv6(source: Ipv6Addr, destination: Ipv6Addr, tcp_segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + tcp_segment.len() + 1);
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(tcp_segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]);
    pseudo.extend_from_slice(tcp_segment);
    checksum16(&pseudo)
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};

    use super::{
        BufferedClientSegment, ClientSegmentView, IPV4_HEADER_LEN, IPV6_HEADER_LEN,
        ParsedTcpPacket, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN,
        build_reset_response, drain_ready_buffered_segments, normalize_client_segment,
        queue_future_segment,
    };
    use crate::config::{
        LoadBalancingConfig, ProbeConfig, TunTcpConfig, UplinkConfig, WsProbeConfig,
    };
    use crate::transport::{AnyWsStream, TcpShadowsocksReader, TcpShadowsocksWriter};
    use crate::tun::SharedTunWriter;
    use crate::tun_tcp::state_machine::SequenceRange;
    use crate::types::{CipherKind, TargetAddr, UplinkTransport, WsTransportMode};
    use crate::uplink::UplinkManager;
    use futures_util::StreamExt;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng, seq::SliceRandom};
    use tokio::fs::File;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Mutex, Notify, mpsc};
    use tokio_tungstenite::{MaybeTlsStream, accept_async, connect_async};
    use url::Url;

    fn parse_action_response(packet: &[u8]) -> Vec<u8> {
        match handle_stateless_packet(packet).unwrap() {
            Some(response) => response,
            None => panic!("expected response"),
        }
    }

    fn handle_stateless_packet(packet: &[u8]) -> Result<Option<Vec<u8>>, anyhow::Error> {
        let parsed = super::parse_tcp_packet(packet)?;
        if (parsed.flags & TCP_FLAG_RST) != 0 {
            return Ok(None);
        }
        Ok(Some(build_reset_response(&parsed)?))
    }

    #[tokio::test]
    async fn tun_tcp_reassembles_out_of_order_client_segments_end_to_end() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40000;
        let remote_port = 80;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                100,
                0,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();

        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(syn_ack.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
        assert_eq!(syn_ack.acknowledgement_number, 101);
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);

        let target = upstream.expect_target().await;
        let (target, consumed) = TargetAddr::from_wire_bytes(&target).unwrap();
        assert_eq!(target, TargetAddr::IpV4(remote_ip, remote_port));
        assert_eq!(consumed, target.to_wire_bytes().unwrap().len());

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                101,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                104,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                b"DEF",
            ))
            .await
            .unwrap();
        let gap_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(gap_ack.acknowledgement_number, 101);
        assert!(upstream.try_recv_chunk().await.is_none());

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                101,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                b"ABC",
            ))
            .await
            .unwrap();
        let full_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(full_ack.acknowledgement_number, 107);
        assert_eq!(upstream.recv_chunk().await, b"ABCDEF");
    }

    #[tokio::test]
    async fn tun_tcp_honors_client_window_and_retransmits_unacked_server_data() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40001;
        let remote_port = 443;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1000,
                0,
                4,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        upstream.send_chunk(b"ABCDEFGH").await;
        let first_data = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(first_data.payload, b"ABCD");
        assert_eq!(first_data.sequence_number, server_next_seq);

        for _ in 0..3 {
            engine
                .handle_packet(&build_client_packet(
                    client_ip,
                    remote_ip,
                    client_port,
                    remote_port,
                    1001,
                    server_next_seq,
                    4,
                    TCP_FLAG_ACK,
                    &[],
                ))
                .await
                .unwrap();
        }

        let retransmitted = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(retransmitted.payload, b"ABCD");
        assert_eq!(retransmitted.sequence_number, server_next_seq);

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq.wrapping_add(4),
                4,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        let second_data = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(second_data.payload, b"EFGH");
        assert_eq!(second_data.sequence_number, server_next_seq.wrapping_add(4));
    }

    #[tokio::test]
    async fn tun_tcp_sends_zero_window_probe_and_resumes_after_window_reopens() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40002;
        let remote_port = 80;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                100,
                0,
                0,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                101,
                server_next_seq,
                0,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        upstream.send_chunk(b"AB").await;
        let probe = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(probe.payload, b"A");
        assert_eq!(probe.sequence_number, server_next_seq);

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                101,
                server_next_seq,
                2,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        let data = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(data.payload, b"AB");
        assert_eq!(data.sequence_number, server_next_seq);
    }

    #[tokio::test]
    async fn tun_tcp_defers_fin_until_buffered_server_data_is_acked() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40003;
        let remote_port = 80;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                500,
                0,
                2,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                501,
                server_next_seq,
                2,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        upstream.send_chunk(b"ABCD").await;
        let first_data = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(first_data.payload, b"AB");

        upstream.close().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                501,
                server_next_seq.wrapping_add(2),
                2,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        let second_data = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(second_data.payload, b"CD");

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                501,
                server_next_seq.wrapping_add(4),
                2,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        let fin = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert!(fin.payload.is_empty());
    }

    #[tokio::test]
    async fn tun_tcp_timeout_retransmit_is_driven_by_flow_timer() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40004;
        let remote_port = 443;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1000,
                0,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        upstream.send_chunk(b"AB").await;
        let first_data = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(first_data.payload, b"AB");

        let key = super::TcpFlowKey {
            version: super::IpVersion::V4,
            client_ip: client_ip.into(),
            client_port,
            remote_ip: remote_ip.into(),
            remote_port,
        };
        let flow = engine
            .inner
            .flows
            .lock()
            .await
            .get(&key)
            .cloned()
            .expect("flow must exist");
        {
            let mut state = flow.lock().await;
            state.retransmission_timeout = Duration::from_millis(200);
            state.maintenance_notify.notify_one();
        }

        let retransmitted = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(retransmitted.sequence_number, first_data.sequence_number);
        assert_eq!(retransmitted.payload, b"AB");
    }

    #[tokio::test]
    async fn tun_tcp_invalid_high_ack_triggers_challenge_ack() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40007;
        let remote_port = 443;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1000,
                0,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq.wrapping_add(100),
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        let ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(ack.flags, TCP_FLAG_ACK);
        assert_eq!(ack.acknowledgement_number, 1001);
    }

    #[tokio::test]
    async fn tun_tcp_invalid_rst_in_window_is_challenge_acked() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40008;
        let remote_port = 443;
        let key = super::TcpFlowKey {
            version: super::IpVersion::V4,
            client_ip: client_ip.into(),
            client_port,
            remote_ip: remote_ip.into(),
            remote_port,
        };

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1000,
                0,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1002,
                server_next_seq,
                4096,
                TCP_FLAG_RST,
                &[],
            ))
            .await
            .unwrap();

        let ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(ack.flags, TCP_FLAG_ACK);
        assert_eq!(ack.acknowledgement_number, 1001);
        assert!(engine.inner.flows.lock().await.get(&key).is_some());
    }

    #[tokio::test]
    async fn tun_tcp_unexpected_syn_in_established_flow_is_challenge_acked() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40009;
        let remote_port = 443;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1000,
                0,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();

        let ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(ack.flags, TCP_FLAG_ACK);
        assert_eq!(ack.acknowledgement_number, 1001);
    }

    #[tokio::test]
    async fn tun_tcp_paws_rejects_stale_timestamp_segment() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40010;
        let remote_port = 443;

        engine
            .handle_packet(&build_client_packet_with_options(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1000,
                0,
                4096,
                TCP_FLAG_SYN,
                &[8, 10, 0, 0, 0, 20, 0, 0, 0, 0, 1, 1],
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet_with_options(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[8, 10, 0, 0, 0, 21, 0, 0, 0, 20, 1, 1],
                &[],
            ))
            .await
            .unwrap();

        engine
            .handle_packet(&build_client_packet_with_options(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[8, 10, 0, 0, 0, 19, 0, 0, 0, 20, 1, 1],
                b"bad",
            ))
            .await
            .unwrap();

        let ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(ack.flags, TCP_FLAG_ACK);
        assert_eq!(ack.acknowledgement_number, 1001);
        assert!(upstream.try_recv_chunk().await.is_none());
    }

    #[tokio::test]
    async fn tun_tcp_respects_peer_mss_for_server_segments() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40011;
        let remote_port = 443;

        engine
            .handle_packet(&build_client_packet_with_options(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1000,
                0,
                4096,
                TCP_FLAG_SYN,
                &[2, 4, 0x02, 0x58],
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                1001,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        upstream.send_chunk(&vec![b'X'; 1000]).await;
        let data = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(data.payload.len(), 600);
    }

    #[tokio::test]
    async fn tun_tcp_client_fin_transitions_through_last_ack() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40005;
        let remote_port = 80;

        let key = super::TcpFlowKey {
            version: super::IpVersion::V4,
            client_ip: client_ip.into(),
            client_port,
            remote_ip: remote_ip.into(),
            remote_port,
        };

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                500,
                0,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                501,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                501,
                server_next_seq,
                4096,
                TCP_FLAG_ACK | TCP_FLAG_FIN,
                &[],
            ))
            .await
            .unwrap();
        let fin_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(fin_ack.flags, TCP_FLAG_ACK);
        assert_eq!(fin_ack.acknowledgement_number, 502);
        let flow = engine
            .inner
            .flows
            .lock()
            .await
            .get(&key)
            .cloned()
            .expect("flow must remain after client FIN");
        assert_eq!(flow.lock().await.status, super::TcpFlowStatus::CloseWait);

        upstream.close().await;
        let server_fin = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(server_fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);
        let flow = engine
            .inner
            .flows
            .lock()
            .await
            .get(&key)
            .cloned()
            .expect("flow must remain in LAST_ACK");
        assert_eq!(flow.lock().await.status, super::TcpFlowStatus::LastAck);

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                502,
                server_next_seq.wrapping_add(1),
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(engine.inner.flows.lock().await.get(&key).is_none());
    }

    #[tokio::test]
    async fn tun_tcp_server_fin_transitions_through_time_wait() {
        let upstream = TestTcpUpstream::start().await;
        let manager = build_test_manager(upstream.url()).await;
        let (writer, mut capture) = TunCapture::new().await;
        let engine = super::TunTcpEngine::new(
            writer,
            manager,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let client_ip = Ipv4Addr::new(10, 0, 0, 2);
        let remote_ip = Ipv4Addr::new(8, 8, 8, 8);
        let client_port = 40006;
        let remote_port = 80;

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                700,
                0,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap();
        let syn_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        let server_next_seq = syn_ack.sequence_number.wrapping_add(1);
        let _ = upstream.expect_target().await;

        let time_wait_key = super::TcpFlowKey {
            version: super::IpVersion::V4,
            client_ip: client_ip.into(),
            client_port,
            remote_ip: remote_ip.into(),
            remote_port,
        };

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                701,
                server_next_seq,
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();

        upstream.close().await;
        let server_fin = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(server_fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                701,
                server_next_seq.wrapping_add(1),
                4096,
                TCP_FLAG_ACK,
                &[],
            ))
            .await
            .unwrap();
        let flow = engine
            .inner
            .flows
            .lock()
            .await
            .get(&time_wait_key)
            .cloned()
            .expect("flow must remain in FIN_WAIT_2");
        assert_eq!(flow.lock().await.status, super::TcpFlowStatus::FinWait2);

        engine
            .handle_packet(&build_client_packet(
                client_ip,
                remote_ip,
                client_port,
                remote_port,
                701,
                server_next_seq.wrapping_add(1),
                4096,
                TCP_FLAG_ACK | TCP_FLAG_FIN,
                &[],
            ))
            .await
            .unwrap();
        let final_ack = super::parse_tcp_packet(&capture.next_packet().await).unwrap();
        assert_eq!(final_ack.flags, TCP_FLAG_ACK);
        assert_eq!(final_ack.acknowledgement_number, 702);

        let flow = engine
            .inner
            .flows
            .lock()
            .await
            .get(&time_wait_key)
            .cloned()
            .expect("flow must stay alive in TIME_WAIT");
        {
            let mut state = flow.lock().await;
            assert_eq!(state.status, super::TcpFlowStatus::TimeWait);
            state.status_since =
                Instant::now() - super::TCP_TIME_WAIT_TIMEOUT - Duration::from_millis(1);
            state.maintenance_notify.notify_one();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            engine
                .inner
                .flows
                .lock()
                .await
                .get(&time_wait_key)
                .is_none()
        );
    }

    #[test]
    fn ipv4_syn_generates_rst_ack() {
        let packet = build_client_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            40000,
            80,
            1,
            0,
            0x4000,
            TCP_FLAG_SYN,
            &[],
        );
        let response = parse_action_response(&packet);
        assert_eq!(response[9], 6);
        assert_eq!(response[IPV4_HEADER_LEN + 13], TCP_FLAG_RST | TCP_FLAG_ACK);
    }

    #[test]
    fn ipv6_ack_generates_rst() {
        let packet = build_client_ipv6_packet_with_options(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            40000,
            80,
            1,
            5,
            0x4000,
            TCP_FLAG_ACK,
            &[],
            &[],
        );
        let response = parse_action_response(&packet);
        assert_eq!(response[6], 6);
        assert_eq!(response[IPV6_HEADER_LEN + 13], TCP_FLAG_RST);
    }

    #[test]
    fn rst_packets_are_ignored() {
        let packet = build_client_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            40000,
            80,
            1,
            5,
            0x4000,
            TCP_FLAG_RST | TCP_FLAG_ACK,
            &[],
        );
        assert!(handle_stateless_packet(&packet).unwrap().is_none());
    }

    #[test]
    fn parsed_tcp_packet_keeps_payload() {
        let packet = build_client_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            40000,
            80,
            1,
            5,
            0x4000,
            TCP_FLAG_ACK,
            b"abc",
        );
        let parsed: ParsedTcpPacket = super::parse_tcp_packet(&packet).unwrap();
        assert_eq!(parsed.flags, TCP_FLAG_ACK);
        assert_eq!(parsed.payload, b"abc");
        assert_eq!(parsed.sequence_number, 1);
        assert_eq!(parsed.acknowledgement_number, 5);
    }

    #[test]
    fn normalize_client_segment_trims_retransmitted_prefix() {
        let packet = ParsedTcpPacket {
            version: super::IpVersion::V4,
            source_ip: "10.0.0.1".parse().unwrap(),
            destination_ip: "8.8.8.8".parse().unwrap(),
            source_port: 12345,
            destination_port: 80,
            sequence_number: 100,
            acknowledgement_number: 0,
            window_size: 4096,
            max_segment_size: None,
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
            timestamp_value: None,
            timestamp_echo_reply: None,
            flags: TCP_FLAG_ACK,
            payload: b"abcdef".to_vec(),
        };

        let segment = normalize_client_segment(&packet, 103);
        assert_eq!(segment.payload, b"def");
        assert!(!segment.fin);
    }

    #[test]
    fn normalize_client_segment_keeps_new_fin_after_duplicate_payload() {
        let packet = ParsedTcpPacket {
            version: super::IpVersion::V4,
            source_ip: "10.0.0.1".parse().unwrap(),
            destination_ip: "8.8.8.8".parse().unwrap(),
            source_port: 12345,
            destination_port: 80,
            sequence_number: 100,
            acknowledgement_number: 0,
            window_size: 4096,
            max_segment_size: None,
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
            timestamp_value: None,
            timestamp_echo_reply: None,
            flags: TCP_FLAG_ACK | TCP_FLAG_FIN,
            payload: b"abc".to_vec(),
        };

        let segment: ClientSegmentView = normalize_client_segment(&packet, 103);
        assert!(segment.payload.is_empty());
        assert!(segment.fin);
    }

    #[test]
    fn normalize_client_segment_drops_fully_duplicate_fin() {
        let packet = ParsedTcpPacket {
            version: super::IpVersion::V4,
            source_ip: "10.0.0.1".parse().unwrap(),
            destination_ip: "8.8.8.8".parse().unwrap(),
            source_port: 12345,
            destination_port: 80,
            sequence_number: 100,
            acknowledgement_number: 0,
            window_size: 4096,
            max_segment_size: None,
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
            timestamp_value: None,
            timestamp_echo_reply: None,
            flags: TCP_FLAG_ACK | TCP_FLAG_FIN,
            payload: b"abc".to_vec(),
        };

        let segment: ClientSegmentView = normalize_client_segment(&packet, 104);
        assert!(segment.payload.is_empty());
        assert!(!segment.fin);
    }

    #[test]
    fn duplicate_syn_is_detected() {
        let packet = ParsedTcpPacket {
            version: super::IpVersion::V4,
            source_ip: "10.0.0.1".parse().unwrap(),
            destination_ip: "8.8.8.8".parse().unwrap(),
            source_port: 12345,
            destination_port: 80,
            sequence_number: 41,
            acknowledgement_number: 0,
            window_size: 4096,
            max_segment_size: None,
            window_scale: Some(4),
            sack_permitted: true,
            sack_blocks: Vec::new(),
            timestamp_value: None,
            timestamp_echo_reply: None,
            flags: TCP_FLAG_SYN,
            payload: Vec::new(),
        };
        assert!(super::is_duplicate_syn(&packet, 42));
    }

    #[test]
    fn queue_future_segment_deduplicates_identical_packet() {
        let packet = ParsedTcpPacket {
            version: super::IpVersion::V4,
            source_ip: "10.0.0.1".parse().unwrap(),
            destination_ip: "8.8.8.8".parse().unwrap(),
            source_port: 12345,
            destination_port: 80,
            sequence_number: 200,
            acknowledgement_number: 0,
            window_size: 4096,
            max_segment_size: None,
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
            timestamp_value: None,
            timestamp_echo_reply: None,
            flags: TCP_FLAG_ACK,
            payload: b"later".to_vec(),
        };
        let mut pending = VecDeque::new();

        queue_future_segment(&mut pending, &packet, 100);
        queue_future_segment(&mut pending, &packet, 100);

        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn drain_ready_buffered_segments_reassembles_contiguous_tail() {
        let mut expected_seq = 103;
        let mut pending = VecDeque::new();
        let first = ParsedTcpPacket {
            version: super::IpVersion::V4,
            source_ip: "10.0.0.1".parse().unwrap(),
            destination_ip: "8.8.8.8".parse().unwrap(),
            source_port: 12345,
            destination_port: 80,
            sequence_number: 106,
            acknowledgement_number: 0,
            window_size: 4096,
            max_segment_size: None,
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
            timestamp_value: None,
            timestamp_echo_reply: None,
            flags: TCP_FLAG_ACK,
            payload: b"ghi".to_vec(),
        };
        let second = ParsedTcpPacket {
            sequence_number: 103,
            payload: b"def".to_vec(),
            ..first.clone()
        };
        queue_future_segment(&mut pending, &first, expected_seq);
        queue_future_segment(&mut pending, &second, expected_seq);
        let mut payload = Vec::new();

        let closed = drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut payload);

        assert!(!closed);
        assert_eq!(expected_seq, 109);
        assert_eq!(payload, b"defghi");
        assert!(pending.is_empty());
    }

    #[test]
    fn drain_ready_buffered_segments_stops_on_gap() {
        let mut expected_seq = 103;
        let mut pending = VecDeque::from([BufferedClientSegment {
            sequence_number: 106,
            flags: TCP_FLAG_ACK,
            payload: b"ghi".to_vec(),
        }]);
        let mut payload = Vec::new();

        let closed = drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut payload);

        assert!(!closed);
        assert_eq!(expected_seq, 103);
        assert!(payload.is_empty());
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn drain_ready_buffered_segments_closes_on_buffered_fin() {
        let mut expected_seq = 103;
        let mut pending = VecDeque::from([BufferedClientSegment {
            sequence_number: 103,
            flags: TCP_FLAG_ACK | TCP_FLAG_FIN,
            payload: b"def".to_vec(),
        }]);
        let mut payload = Vec::new();

        let closed = drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut payload);

        assert!(closed);
        assert_eq!(expected_seq, 107);
        assert_eq!(payload, b"def");
        assert!(pending.is_empty());
    }

    #[test]
    fn parse_tcp_packet_extracts_window_scale_and_sack_blocks() {
        let packet = build_client_packet_with_options(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            40004,
            443,
            10,
            100,
            2048,
            TCP_FLAG_ACK,
            &[
                3, 3, 7, 4, 2, 1, 1, 5, 10, 0, 0, 0, 120, 0, 0, 0, 140, 1, 1, 1,
            ],
            &[],
        );
        let parsed = super::parse_tcp_packet(&packet).unwrap();
        assert_eq!(parsed.window_scale, Some(7));
        assert!(parsed.sack_permitted);
        assert_eq!(parsed.sack_blocks, vec![(120, 140)]);
    }

    #[test]
    fn parse_tcp_packet_extracts_mss_and_timestamps() {
        let packet = build_client_packet_with_options(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            40004,
            443,
            10,
            100,
            2048,
            TCP_FLAG_ACK,
            &[2, 4, 0x05, 0xb4, 8, 10, 0, 0, 0, 9, 0, 0, 0, 7, 1, 1],
            &[],
        );
        let parsed = super::parse_tcp_packet(&packet).unwrap();
        assert_eq!(parsed.max_segment_size, Some(1460));
        assert_eq!(parsed.timestamp_value, Some(9));
        assert_eq!(parsed.timestamp_echo_reply, Some(7));
    }

    #[test]
    fn parse_tcp_packet_rejects_invalid_ipv4_header_checksum() {
        let mut packet = build_client_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            40004,
            443,
            10,
            100,
            2048,
            TCP_FLAG_ACK,
            b"hello",
        );
        packet[12] ^= 0x01;
        let error = super::parse_tcp_packet(&packet).unwrap_err();
        assert!(error.to_string().contains("invalid IPv4 header checksum"));
    }

    #[test]
    fn parse_tcp_packet_rejects_invalid_tcp_checksum_ipv4() {
        let mut packet = build_client_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            40004,
            443,
            10,
            100,
            2048,
            TCP_FLAG_ACK,
            b"hello",
        );
        packet[IPV4_HEADER_LEN + 7] ^= 0x01;
        let error = super::parse_tcp_packet(&packet).unwrap_err();
        assert!(error.to_string().contains("invalid TCP checksum"));
    }

    #[test]
    fn parse_tcp_packet_rejects_invalid_tcp_checksum_ipv6() {
        let client_ip = Ipv6Addr::LOCALHOST;
        let remote_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let mut packet = build_client_ipv6_packet_with_options(
            client_ip,
            remote_ip,
            40004,
            443,
            10,
            100,
            2048,
            TCP_FLAG_ACK,
            &[],
            b"hello",
        );
        packet[IPV6_HEADER_LEN + 5] ^= 0x01;
        let error = super::parse_tcp_packet(&packet).unwrap_err();
        assert!(error.to_string().contains("invalid TCP checksum"));
    }

    #[test]
    fn parse_tcp_packet_accepts_ipv6_destination_options_before_tcp() {
        let client_ip = Ipv6Addr::LOCALHOST;
        let remote_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let packet = build_client_ipv6_packet_with_extension_headers(
            client_ip,
            remote_ip,
            40004,
            443,
            10,
            100,
            2048,
            TCP_FLAG_ACK,
            &[vec![
                super::IPV6_NEXT_HEADER_DESTINATION_OPTIONS,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]],
            &tcp_option_pad(vec![2, 4, 0x05, 0xb4]),
            b"hello",
        );
        let parsed = super::parse_tcp_packet(&packet).unwrap();
        assert_eq!(parsed.version, super::IpVersion::V6);
        assert_eq!(parsed.source_port, 40004);
        assert_eq!(parsed.destination_port, 443);
        assert_eq!(parsed.max_segment_size, Some(1460));
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn parse_tcp_packet_rejects_ipv6_fragment_header() {
        let client_ip = Ipv6Addr::LOCALHOST;
        let remote_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let packet = build_client_ipv6_packet_with_extension_headers(
            client_ip,
            remote_ip,
            40004,
            443,
            10,
            100,
            2048,
            TCP_FLAG_ACK,
            &[vec![super::IPV6_NEXT_HEADER_FRAGMENT, 0, 0, 0, 0, 0, 0, 0]],
            &[],
            b"hello",
        );
        let error = super::parse_tcp_packet(&packet).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("IPv6 fragments are not supported")
        );
    }

    #[test]
    fn randomized_tcp_packet_round_trip_and_mutation_smoke() {
        let mut rng = StdRng::seed_from_u64(0x5eed_7a11);
        for _ in 0..128 {
            let payload_len = rng.gen_range(0..48);
            let mut payload = vec![0u8; payload_len];
            rng.fill(payload.as_mut_slice());
            let flags = [
                TCP_FLAG_ACK,
                TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                TCP_FLAG_ACK | TCP_FLAG_FIN,
                TCP_FLAG_SYN,
                TCP_FLAG_SYN | TCP_FLAG_ACK,
            ][rng.gen_range(0..5)];
            let payload = if (flags & TCP_FLAG_SYN) != 0 {
                Vec::new()
            } else {
                payload
            };
            let options = match rng.gen_range(0..4) {
                0 => Vec::new(),
                1 => tcp_option_pad(vec![2, 4, 0x05, 0xb4]),
                2 => tcp_option_pad(vec![1, 3, 3, 7]),
                _ => tcp_option_pad(vec![8, 10, 0, 0, 0, 9, 0, 0, 0, 7]),
            };
            let sequence_number = rng.r#gen::<u32>();
            let acknowledgement_number = rng.r#gen::<u32>();
            let window_size = rng.gen_range(1..=u16::MAX);

            if rng.gen_bool(0.5) {
                let client_ip = Ipv4Addr::new(10, 0, 0, rng.gen_range(2..=250));
                let remote_ip = Ipv4Addr::new(8, 8, 4, rng.gen_range(1..=250));
                let packet = build_client_packet_with_options(
                    client_ip,
                    remote_ip,
                    rng.gen_range(1024..=65000),
                    rng.gen_range(1..=65000),
                    sequence_number,
                    acknowledgement_number,
                    window_size,
                    flags,
                    &options,
                    &payload,
                );
                let parsed = super::parse_tcp_packet(&packet).unwrap();
                assert_eq!(parsed.version, super::IpVersion::V4);
                assert_eq!(parsed.sequence_number, sequence_number);
                assert_eq!(parsed.acknowledgement_number, acknowledgement_number);
                assert_eq!(parsed.flags, flags);
                assert_eq!(parsed.payload, payload);

                let mut mutated = packet.clone();
                mutated[IPV4_HEADER_LEN + 4] ^= 0x01;
                assert!(super::parse_tcp_packet(&mutated).is_err());
            } else {
                let client_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, rng.gen_range(2..=250));
                let remote_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.gen_range(2..=250));
                let packet = build_client_ipv6_packet_with_options(
                    client_ip,
                    remote_ip,
                    rng.gen_range(1024..=65000),
                    rng.gen_range(1..=65000),
                    sequence_number,
                    acknowledgement_number,
                    window_size,
                    flags,
                    &options,
                    &payload,
                );
                let parsed = super::parse_tcp_packet(&packet).unwrap();
                assert_eq!(parsed.version, super::IpVersion::V6);
                assert_eq!(parsed.sequence_number, sequence_number);
                assert_eq!(parsed.acknowledgement_number, acknowledgement_number);
                assert_eq!(parsed.flags, flags);
                assert_eq!(parsed.payload, payload);

                let mut mutated = packet.clone();
                mutated[IPV6_HEADER_LEN + 8] ^= 0x01;
                assert!(super::parse_tcp_packet(&mutated).is_err());
            }
        }
    }

    #[test]
    fn randomized_out_of_order_reassembly_smoke() {
        let mut rng = StdRng::seed_from_u64(0x51ce_2026);
        for _ in 0..64 {
            let sequence_start = rng.gen_range(10_000..50_000);
            let total_len = rng.gen_range(12..96);
            let mut original = vec![0u8; total_len];
            rng.fill(original.as_mut_slice());

            let mut segments = Vec::new();
            let mut cursor = 0usize;
            while cursor < total_len {
                let len = rng.gen_range(1..=(total_len - cursor).min(16));
                segments.push((
                    sequence_start + cursor as u32,
                    original[cursor..cursor + len].to_vec(),
                ));
                if cursor > 0 && rng.gen_bool(0.35) {
                    let overlap_start = cursor.saturating_sub(rng.gen_range(1..=cursor.min(4)));
                    segments.push((
                        sequence_start + overlap_start as u32,
                        original[overlap_start..cursor + len].to_vec(),
                    ));
                }
                cursor += len;
            }
            segments.shuffle(&mut rng);

            let mut pending = VecDeque::new();
            for (sequence_number, payload) in segments {
                let packet = ParsedTcpPacket {
                    version: super::IpVersion::V4,
                    source_ip: "10.0.0.1".parse().unwrap(),
                    destination_ip: "8.8.8.8".parse().unwrap(),
                    source_port: 12345,
                    destination_port: 80,
                    sequence_number,
                    acknowledgement_number: 0,
                    window_size: 4096,
                    max_segment_size: None,
                    window_scale: None,
                    sack_permitted: false,
                    sack_blocks: Vec::new(),
                    timestamp_value: None,
                    timestamp_echo_reply: None,
                    flags: TCP_FLAG_ACK,
                    payload,
                };
                queue_future_segment(&mut pending, &packet, sequence_start);
            }

            let mut expected_seq = sequence_start;
            let mut reassembled = Vec::new();
            let closed =
                drain_ready_buffered_segments(&mut expected_seq, &mut pending, &mut reassembled);
            assert!(!closed);
            assert_eq!(expected_seq, sequence_start + total_len as u32);
            assert_eq!(reassembled, original);
        }
    }

    #[tokio::test]
    async fn build_flow_syn_ack_advertises_mss_and_timestamps() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_sack_permitted = true;
        state.timestamps_enabled = true;
        state.recent_client_timestamp = Some(1234);
        state.server_timestamp_offset = 7;

        let packet = super::build_flow_syn_ack_packet(&state, 900, 101).unwrap();
        let parsed = super::parse_tcp_packet(&packet).unwrap();
        assert_eq!(parsed.flags, TCP_FLAG_SYN | TCP_FLAG_ACK);
        assert_eq!(
            parsed.max_segment_size,
            Some(super::MAX_SERVER_SEGMENT_PAYLOAD as u16)
        );
        assert!(parsed.sack_permitted);
        assert_eq!(parsed.timestamp_echo_reply, Some(1234));
        assert!(parsed.timestamp_value.unwrap_or_default() >= 7);
    }

    #[tokio::test]
    async fn process_server_ack_marks_sacked_segments_without_cumulative_ack() {
        let mut state = tcp_flow_state_for_tests().await;
        state.last_client_ack = 1000;
        state.server_seq = 1012;
        state.client_window = 8192;
        state.client_window_end = 9192;
        state.unacked_server_segments = VecDeque::from([
            super::ServerSegment {
                sequence_number: 1000,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"AAAA".to_vec(),
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                retransmits: 0,
            },
            super::ServerSegment {
                sequence_number: 1004,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"BBBB".to_vec(),
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                retransmits: 0,
            },
        ]);

        let effect = super::process_server_ack(&mut state, 1000, &[(1004, 1008)]);
        assert_eq!(effect.bytes_acked, 0);
        assert!(!effect.retransmit_now);
        assert_eq!(
            state.sack_scoreboard,
            vec![SequenceRange {
                start: 1004,
                end: 1008,
            }]
        );
    }

    #[tokio::test]
    async fn process_server_ack_partial_ack_in_fast_recovery_requests_next_retransmit() {
        let mut state = tcp_flow_state_for_tests().await;
        state.last_client_ack = 1000;
        state.server_seq = 1016;
        state.slow_start_threshold = 2400;
        state.congestion_window = 4000;
        state.fast_recovery_end = Some(1016);
        state.sack_scoreboard = vec![SequenceRange {
            start: 1008,
            end: 1012,
        }];
        state.unacked_server_segments = VecDeque::from([
            super::ServerSegment {
                sequence_number: 1000,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"AAAA".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_millis(200),
                retransmits: 0,
            },
            super::ServerSegment {
                sequence_number: 1004,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"BBBB".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 1,
            },
            super::ServerSegment {
                sequence_number: 1008,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"CCCC".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 0,
            },
            super::ServerSegment {
                sequence_number: 1012,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"DDDD".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 0,
            },
        ]);

        let effect = super::process_server_ack(&mut state, 1004, &[(1008, 1012)]);
        assert_eq!(effect.bytes_acked, 4);
        assert!(!effect.grow_congestion_window);
        assert!(effect.retransmit_now);
        assert_eq!(
            state.congestion_window,
            state.slow_start_threshold + super::MAX_SERVER_SEGMENT_PAYLOAD
        );
        assert_eq!(state.fast_recovery_end, Some(1016));
    }

    #[tokio::test]
    async fn process_server_ack_exits_fast_recovery_once_recovery_point_is_acked() {
        let mut state = tcp_flow_state_for_tests().await;
        state.last_client_ack = 1000;
        state.server_seq = 1016;
        state.slow_start_threshold = 2400;
        state.congestion_window = 4000;
        state.fast_recovery_end = Some(1016);
        state.unacked_server_segments = VecDeque::from([
            super::ServerSegment {
                sequence_number: 1000,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"AAAA".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_millis(200),
                retransmits: 1,
            },
            super::ServerSegment {
                sequence_number: 1004,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"BBBB".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 1,
            },
        ]);

        let effect = super::process_server_ack(&mut state, 1008, &[]);
        assert_eq!(effect.bytes_acked, 8);
        assert!(!effect.grow_congestion_window);
        assert!(!effect.retransmit_now);
        assert!(state.fast_recovery_end.is_none());
        assert_eq!(state.congestion_window, state.slow_start_threshold);
    }

    #[tokio::test]
    async fn update_client_send_window_uses_rfc_precedence_rules() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_window = 4096;
        state.client_window_end = 5096;
        state.client_window_update_seq = 100;
        state.client_window_update_ack = 1000;

        let stale = ParsedTcpPacket {
            version: super::IpVersion::V4,
            source_ip: "10.0.0.2".parse().unwrap(),
            destination_ip: "8.8.8.8".parse().unwrap(),
            source_port: 40000,
            destination_port: 443,
            sequence_number: 99,
            acknowledgement_number: 1000,
            window_size: 1,
            max_segment_size: None,
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
            timestamp_value: None,
            timestamp_echo_reply: None,
            flags: TCP_FLAG_ACK,
            payload: Vec::new(),
        };
        super::update_client_send_window(&mut state, &stale);
        assert_eq!(state.client_window, 4096);
        assert_eq!(state.client_window_end, 5096);

        let newer = ParsedTcpPacket {
            sequence_number: 101,
            window_size: 2,
            ..stale
        };
        super::update_client_send_window(&mut state, &newer);
        assert_eq!(state.client_window, 2);
        assert_eq!(state.client_window_end, 1002);
        assert_eq!(state.client_window_update_seq, 101);
        assert_eq!(state.client_window_update_ack, 1000);
    }

    #[tokio::test]
    async fn zero_window_persist_backoff_doubles_until_cap() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_window = 0;
        state.client_window_end = state.server_seq;
        state.pending_server_data.push_back(b"ABC".to_vec());

        let first = super::maybe_emit_zero_window_probe(&mut state).unwrap();
        assert!(first.is_some());
        assert_eq!(
            state.zero_window_probe_backoff,
            super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL.saturating_mul(2)
        );
        let first_deadline = state.next_zero_window_probe_at.unwrap();

        state.next_zero_window_probe_at = Some(Instant::now() - Duration::from_millis(1));
        let second = super::maybe_emit_zero_window_probe(&mut state).unwrap();
        assert!(second.is_some());
        assert!(state.next_zero_window_probe_at.unwrap() > first_deadline);

        super::reset_zero_window_persist(&mut state);
        assert_eq!(
            state.zero_window_probe_backoff,
            super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL
        );
        assert!(state.next_zero_window_probe_at.is_none());
    }

    #[tokio::test]
    async fn build_flow_ack_packet_advertises_sack_blocks_for_buffered_segments() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_sack_permitted = true;
        state.pending_client_segments = VecDeque::from([
            BufferedClientSegment {
                sequence_number: 120,
                flags: TCP_FLAG_ACK,
                payload: b"efgh".to_vec(),
            },
            BufferedClientSegment {
                sequence_number: 112,
                flags: TCP_FLAG_ACK,
                payload: b"abcd".to_vec(),
            },
        ]);
        let packet = super::build_flow_ack_packet(
            &state,
            state.server_seq,
            state.client_next_seq,
            TCP_FLAG_ACK,
        )
        .unwrap();
        let parsed = super::parse_tcp_packet(&packet).unwrap();
        assert_eq!(parsed.sack_blocks, vec![(112, 116), (120, 124)]);
    }

    #[tokio::test]
    async fn build_flow_ack_packet_limits_sack_blocks_when_timestamps_are_enabled() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_sack_permitted = true;
        state.timestamps_enabled = true;
        state.recent_client_timestamp = Some(55);
        state.pending_client_segments = VecDeque::from([
            BufferedClientSegment {
                sequence_number: 112,
                flags: TCP_FLAG_ACK,
                payload: b"aaaa".to_vec(),
            },
            BufferedClientSegment {
                sequence_number: 120,
                flags: TCP_FLAG_ACK,
                payload: b"bbbb".to_vec(),
            },
            BufferedClientSegment {
                sequence_number: 128,
                flags: TCP_FLAG_ACK,
                payload: b"cccc".to_vec(),
            },
            BufferedClientSegment {
                sequence_number: 136,
                flags: TCP_FLAG_ACK,
                payload: b"dddd".to_vec(),
            },
        ]);

        let packet = super::build_flow_ack_packet(
            &state,
            state.server_seq,
            state.client_next_seq,
            TCP_FLAG_ACK,
        )
        .unwrap();
        let parsed = super::parse_tcp_packet(&packet).unwrap();
        assert_eq!(parsed.sack_blocks, vec![(112, 116), (120, 124), (128, 132)]);
        assert_eq!(parsed.timestamp_echo_reply, Some(55));
    }

    #[tokio::test]
    async fn retransmit_prefers_unsacked_hole_before_sacked_tail() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_next_seq = 500;
        state.sack_scoreboard = vec![SequenceRange {
            start: 1004,
            end: 1008,
        }];
        state.unacked_server_segments = VecDeque::from([
            super::ServerSegment {
                sequence_number: 1000,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"AAAA".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 0,
            },
            super::ServerSegment {
                sequence_number: 1004,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"BBBB".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 0,
            },
            super::ServerSegment {
                sequence_number: 1008,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"CCCC".to_vec(),
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 0,
            },
        ]);

        let packet = super::retransmit_oldest_unacked_packet(&mut state)
            .unwrap()
            .unwrap();
        let parsed = super::parse_tcp_packet(&packet).unwrap();
        assert_eq!(parsed.sequence_number, 1000);
        assert_eq!(parsed.payload, b"AAAA");
    }

    #[tokio::test]
    async fn ack_progress_updates_rtt_and_grows_congestion_window() {
        let mut state = tcp_flow_state_for_tests().await;
        state.congestion_window = super::MAX_SERVER_SEGMENT_PAYLOAD;
        state.slow_start_threshold = super::TCP_SERVER_RECV_WINDOW_CAPACITY;

        super::note_ack_progress(&mut state, 600, Some(Duration::from_millis(120)), true);
        assert_eq!(state.smoothed_rtt, Some(Duration::from_millis(120)));
        assert!(state.retransmission_timeout >= Duration::from_millis(200));
        assert_eq!(
            state.congestion_window,
            super::MAX_SERVER_SEGMENT_PAYLOAD + 600
        );
    }

    #[tokio::test]
    async fn timeout_congestion_event_reduces_cwnd_and_backs_off_rto() {
        let mut state = tcp_flow_state_for_tests().await;
        state.congestion_window = super::MAX_SERVER_SEGMENT_PAYLOAD * 8;
        state.slow_start_threshold = super::MAX_SERVER_SEGMENT_PAYLOAD * 8;
        state.retransmission_timeout = Duration::from_millis(800);
        state.unacked_server_segments = VecDeque::from([super::ServerSegment {
            sequence_number: 1000,
            acknowledgement_number: 500,
            flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
            payload: b"AAAA".to_vec(),
            last_sent: Instant::now() - Duration::from_secs(2),
            first_sent: Instant::now() - Duration::from_secs(2),
            retransmits: 0,
        }]);

        super::note_congestion_event(&mut state, true);
        assert_eq!(state.congestion_window, super::MAX_SERVER_SEGMENT_PAYLOAD);
        assert!(state.slow_start_threshold >= super::TCP_MIN_SSTHRESH);
        assert_eq!(state.retransmission_timeout, Duration::from_millis(1600));
    }

    #[tokio::test]
    async fn reassembly_limits_trigger_for_segment_and_byte_pressure() {
        let mut state = tcp_flow_state_for_tests().await;
        state.pending_client_segments = VecDeque::from([
            super::BufferedClientSegment {
                sequence_number: 150,
                flags: TCP_FLAG_ACK,
                payload: vec![1; 32],
            },
            super::BufferedClientSegment {
                sequence_number: 182,
                flags: TCP_FLAG_ACK,
                payload: vec![2; 32],
            },
        ]);
        let config = TunTcpConfig {
            max_buffered_client_segments: 1,
            max_buffered_client_bytes: 48,
            ..test_tun_tcp_config()
        };
        assert!(super::exceeds_client_reassembly_limits(&state, &config));
    }

    #[tokio::test]
    async fn server_backlog_limit_detects_pending_bytes() {
        let mut state = tcp_flow_state_for_tests().await;
        state.pending_server_data = VecDeque::from([vec![1; 128], vec![2; 128]]);
        let config = TunTcpConfig {
            max_pending_server_bytes: 200,
            ..test_tun_tcp_config()
        };
        let pressure =
            super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), false);
        assert!(pressure.exceeded);
    }

    #[tokio::test]
    async fn server_backlog_pressure_allows_brief_window_stall() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_window = 0;
        state.client_window_end = state.server_seq;
        state.pending_server_data = VecDeque::from([vec![1; 256]]);
        let config = TunTcpConfig {
            max_pending_server_bytes: 200,
            ..test_tun_tcp_config()
        };

        let pressure =
            super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), true);

        assert!(pressure.exceeded);
        assert!(!pressure.should_abort);
        assert!(state.backlog_limit_exceeded_since.is_some());
    }

    #[tokio::test]
    async fn server_backlog_pressure_aborts_after_grace_even_without_window_stall() {
        let mut state = tcp_flow_state_for_tests().await;
        state.pending_server_data = VecDeque::from([vec![1; 256]]);
        let config = TunTcpConfig {
            max_pending_server_bytes: 200,
            ..test_tun_tcp_config()
        };
        state.backlog_limit_exceeded_since = Some(Instant::now() - config.backlog_abort_grace);

        let pressure =
            super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), false);

        assert!(pressure.exceeded);
        assert!(pressure.should_abort);
    }

    #[tokio::test]
    async fn server_backlog_pressure_aborts_after_grace_when_stalled() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_window = 0;
        state.client_window_end = state.server_seq;
        state.pending_server_data = VecDeque::from([vec![1; 256]]);
        let config = TunTcpConfig {
            max_pending_server_bytes: 200,
            ..test_tun_tcp_config()
        };
        state.backlog_limit_exceeded_since = Some(Instant::now() - config.backlog_abort_grace);

        let pressure =
            super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), true);

        assert!(pressure.exceeded);
        assert!(pressure.should_abort);
    }

    #[tokio::test]
    async fn server_backlog_pressure_aborts_after_no_ack_progress_timeout() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_window = 0;
        state.client_window_end = state.server_seq;
        state.pending_server_data = VecDeque::from([vec![1; 256]]);
        let config = TunTcpConfig {
            max_pending_server_bytes: 200,
            backlog_abort_grace: Duration::from_secs(60),
            backlog_no_progress_abort: Duration::from_secs(2),
            ..test_tun_tcp_config()
        };
        state.last_ack_progress_at = Instant::now() - config.backlog_no_progress_abort;

        let pressure =
            super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), true);

        assert!(pressure.exceeded);
        assert!(pressure.should_abort);
        assert!(
            pressure.no_progress_ms.unwrap_or_default()
                >= config.backlog_no_progress_abort.as_millis()
        );
    }

    #[tokio::test]
    async fn server_backlog_pressure_aborts_immediately_above_hard_limit() {
        let mut state = tcp_flow_state_for_tests().await;
        state.pending_server_data = VecDeque::from([vec![1; 512]]);
        let config = TunTcpConfig {
            max_pending_server_bytes: 200,
            ..test_tun_tcp_config()
        };

        let pressure =
            super::assess_server_backlog_pressure(&mut state, &config, Instant::now(), false);

        assert!(pressure.exceeded);
        assert!(pressure.should_abort);
    }

    #[tokio::test]
    async fn new_flow_is_removed_when_synack_write_fails() {
        let path = std::env::temp_dir().join(format!(
            "outline-ws-rust-tun-write-fail-{}.bin",
            rand::random::<u64>()
        ));
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .unwrap();
        let writer = SharedTunWriter::new(File::from_std(
            std::fs::OpenOptions::new().read(true).open(&path).unwrap(),
        ));
        let engine = super::TunTcpEngine::new(
            writer,
            build_test_manager(Url::parse("ws://127.0.0.1:9/tcp").unwrap()).await,
            128,
            Duration::from_secs(60),
            test_tun_tcp_config(),
        );

        let error = engine
            .handle_packet(&build_client_packet(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(8, 8, 8, 8),
                40010,
                443,
                100,
                0,
                4096,
                TCP_FLAG_SYN,
                &[],
            ))
            .await
            .unwrap_err();

        let error_text = format!("{error:#}");
        assert!(
            error_text.contains("failed to write packet to TUN")
                || error_text.contains("failed to flush TUN packet"),
            "{error_text}"
        );
        assert!(engine.inner.flows.lock().await.is_empty());
        assert!(engine.inner.pending_connects.lock().await.is_empty());

        let _ = std::fs::remove_file(path);
    }

    async fn build_test_manager(tcp_ws_url: Url) -> UplinkManager {
        UplinkManager::new(
            vec![UplinkConfig {
                name: "test".to_string(),
                transport: UplinkTransport::Websocket,
                tcp_ws_url: Some(tcp_ws_url),
                tcp_ws_mode: WsTransportMode::Http1,
                udp_ws_url: None,
                udp_ws_mode: WsTransportMode::Http1,
                tcp_addr: None,
                udp_addr: None,
                cipher: CipherKind::Chacha20IetfPoly1305,
                password: "Secret0".to_string(),
                weight: 1.0,
                fwmark: None,
                ipv6_first: false,
            }],
            ProbeConfig {
                interval: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                max_concurrent: 2,
                max_dials: 1,
                min_failures: 1,
                attempts: 1,
                ws: WsProbeConfig { enabled: false },
                http: None,
                dns: None,
            },
            LoadBalancingConfig {
                mode: crate::config::LoadBalancingMode::ActiveActive,
                routing_scope: crate::config::RoutingScope::PerFlow,
                sticky_ttl: Duration::from_secs(300),
                hysteresis: Duration::from_millis(50),
                failure_cooldown: Duration::from_secs(10),
                warm_standby_tcp: 0,
                warm_standby_udp: 0,
                rtt_ewma_alpha: 0.3,
                failure_penalty: Duration::from_millis(500),
                failure_penalty_max: Duration::from_secs(30),
                failure_penalty_halflife: Duration::from_secs(60),
                h3_downgrade_duration: Duration::from_secs(60),
                udp_ws_keepalive_interval: None,
                tcp_ws_standby_keepalive_interval: None,
                auto_failback: false,
            },
        )
        .unwrap()
    }

    fn test_tun_tcp_config() -> TunTcpConfig {
        TunTcpConfig {
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
            half_close_timeout: Duration::from_secs(15),
            max_pending_server_bytes: 1_048_576,
            backlog_abort_grace: Duration::from_secs(3),
            backlog_hard_limit_multiplier: 2,
            backlog_no_progress_abort: Duration::from_secs(8),
            max_buffered_client_segments: 4096,
            max_buffered_client_bytes: 262_144,
            max_retransmits: 12,
        }
    }

    fn build_client_packet(
        client_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        client_port: u16,
        remote_port: u16,
        sequence_number: u32,
        acknowledgement_number: u32,
        window_size: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        build_client_packet_with_options(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            sequence_number,
            acknowledgement_number,
            window_size,
            flags,
            &[],
            payload,
        )
    }

    fn build_client_packet_with_options(
        client_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        client_port: u16,
        remote_port: u16,
        sequence_number: u32,
        acknowledgement_number: u32,
        window_size: u16,
        flags: u8,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        super::build_response_packet_custom(
            super::IpVersion::V4,
            client_ip.into(),
            remote_ip.into(),
            client_port,
            remote_port,
            sequence_number,
            acknowledgement_number,
            flags,
            window_size,
            options,
            payload,
        )
        .unwrap()
    }

    fn build_client_ipv6_packet_with_options(
        client_ip: Ipv6Addr,
        remote_ip: Ipv6Addr,
        client_port: u16,
        remote_port: u16,
        sequence_number: u32,
        acknowledgement_number: u32,
        window_size: u16,
        flags: u8,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        super::build_response_packet_custom(
            super::IpVersion::V6,
            client_ip.into(),
            remote_ip.into(),
            client_port,
            remote_port,
            sequence_number,
            acknowledgement_number,
            flags,
            window_size,
            options,
            payload,
        )
        .unwrap()
    }

    fn tcp_option_pad(mut options: Vec<u8>) -> Vec<u8> {
        while options.len() % 4 != 0 {
            options.push(1);
        }
        options
    }

    fn build_client_ipv6_packet_with_extension_headers(
        client_ip: Ipv6Addr,
        remote_ip: Ipv6Addr,
        client_port: u16,
        remote_port: u16,
        sequence_number: u32,
        acknowledgement_number: u32,
        window_size: u16,
        flags: u8,
        extension_headers: &[Vec<u8>],
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_packet = build_client_ipv6_packet_with_options(
            client_ip,
            remote_ip,
            client_port,
            remote_port,
            sequence_number,
            acknowledgement_number,
            window_size,
            flags,
            options,
            payload,
        );

        let tcp_segment = &tcp_packet[IPV6_HEADER_LEN..];
        let extension_len: usize = extension_headers.iter().map(Vec::len).sum();
        let total_len = IPV6_HEADER_LEN + extension_len + tcp_segment.len();
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((extension_len + tcp_segment.len()) as u16).to_be_bytes());
        packet[6] = extension_headers
            .first()
            .and_then(|header| header.first().copied())
            .unwrap_or(super::IPV6_NEXT_HEADER_TCP);
        packet[7] = 64;
        packet[8..24].copy_from_slice(&client_ip.octets());
        packet[24..40].copy_from_slice(&remote_ip.octets());

        let mut offset = IPV6_HEADER_LEN;
        for (index, header) in extension_headers.iter().enumerate() {
            let mut encoded = header.clone();
            let next = if index + 1 < extension_headers.len() {
                extension_headers[index + 1][0]
            } else {
                super::IPV6_NEXT_HEADER_TCP
            };
            encoded[0] = next;
            packet[offset..offset + encoded.len()].copy_from_slice(&encoded);
            offset += encoded.len();
        }
        packet[offset..].copy_from_slice(tcp_segment);
        packet
    }

    async fn tcp_flow_state_for_tests() -> super::TcpFlowState {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            while ws.next().await.is_some() {}
        });

        let (ws_stream, _) = connect_async(format!("ws://{addr}/")).await.unwrap();
        let ws = AnyWsStream::Http1 { inner: ws_stream };
        let (sink, _stream) = ws.split();
        let cipher = CipherKind::Chacha20IetfPoly1305;
        let master_key = cipher.derive_master_key("Secret0").unwrap();
        let (close_signal, _close_rx) = tokio::sync::watch::channel(false);
        super::TcpFlowState {
            id: 1,
            key: super::TcpFlowKey {
                version: super::IpVersion::V4,
                client_ip: "10.0.0.2".parse().unwrap(),
                client_port: 40000,
                remote_ip: "8.8.8.8".parse().unwrap(),
                remote_port: 443,
            },
            uplink_index: 0,
            uplink_name: "test".to_string(),
            upstream_writer: Some(Arc::new(Mutex::new({
                let (writer, _ctrl_tx) = TcpShadowsocksWriter::connect(
                    sink,
                    cipher,
                    &master_key,
                    super::UpstreamTransportGuard::new("test", "tcp"),
                )
                .await
                .unwrap();
                writer
            }))),
            close_signal,
            maintenance_notify: Arc::new(Notify::new()),
            status: super::TcpFlowStatus::Established,
            client_next_seq: 100,
            client_window_scale: 0,
            client_sack_permitted: false,
            client_max_segment_size: None,
            timestamps_enabled: false,
            recent_client_timestamp: None,
            server_timestamp_offset: 0,
            client_window: 4096,
            client_window_end: 5096,
            client_window_update_seq: 100,
            client_window_update_ack: 1000,
            server_seq: 1000,
            last_client_ack: 1000,
            duplicate_ack_count: 0,
            fast_recovery_end: None,
            receive_window_capacity: 262_144,
            smoothed_rtt: None,
            rttvar: super::TCP_INITIAL_RTO / 2,
            retransmission_timeout: super::TCP_INITIAL_RTO,
            congestion_window: super::MAX_SERVER_SEGMENT_PAYLOAD * super::TCP_INITIAL_CWND_SEGMENTS,
            slow_start_threshold: super::TCP_SERVER_RECV_WINDOW_CAPACITY,
            pending_server_data: VecDeque::new(),
            backlog_limit_exceeded_since: None,
            last_ack_progress_at: Instant::now(),
            pending_client_data: VecDeque::new(),
            unacked_server_segments: VecDeque::new(),
            sack_scoreboard: Vec::new(),
            pending_client_segments: VecDeque::new(),
            server_fin_pending: false,
            zero_window_probe_backoff: super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL,
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
            created_at: Instant::now(),
            status_since: Instant::now(),
            last_seen: Instant::now(),
        }
    }

    struct TunCapture {
        path: PathBuf,
        offset: usize,
    }

    impl TunCapture {
        async fn new() -> (SharedTunWriter, Self) {
            let path = std::env::temp_dir().join(format!(
                "outline-ws-rust-tun-capture-{}.bin",
                rand::random::<u64>()
            ));
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let writer = SharedTunWriter::new(File::from_std(file));
            (writer, Self { path, offset: 0 })
        }

        async fn next_packet(&mut self) -> Vec<u8> {
            for _ in 0..100 {
                let data = tokio::fs::read(&self.path).await.unwrap_or_default();
                if data.len() > self.offset {
                    let remaining = &data[self.offset..];
                    if let Some(packet_len) = packet_length(remaining) {
                        if remaining.len() >= packet_len {
                            let packet = remaining[..packet_len].to_vec();
                            self.offset += packet_len;
                            return packet;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("timed out waiting for captured TUN packet");
        }
    }

    impl Drop for TunCapture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn packet_length(data: &[u8]) -> Option<usize> {
        match data.first().map(|byte| byte >> 4)? {
            4 if data.len() >= 4 => Some(u16::from_be_bytes([data[2], data[3]]) as usize),
            6 if data.len() >= 6 => {
                Some(IPV6_HEADER_LEN + u16::from_be_bytes([data[4], data[5]]) as usize)
            }
            _ => None,
        }
    }

    struct TestTcpUpstream {
        addr: SocketAddr,
        target_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        chunk_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
        send_tx: mpsc::UnboundedSender<Vec<u8>>,
        _accepted: Arc<AtomicUsize>,
    }

    impl TestTcpUpstream {
        async fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accepted = Arc::new(AtomicUsize::new(0));
            let accepted_task = Arc::clone(&accepted);
            let (target_tx, target_rx) = mpsc::unbounded_channel();
            let (chunk_tx, chunk_rx) = mpsc::unbounded_channel();
            let (send_tx, send_rx) = mpsc::unbounded_channel();

            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                accepted_task.fetch_add(1, Ordering::SeqCst);
                let _ = handle_test_tcp_upstream(stream, target_tx, chunk_tx, send_rx).await;
            });

            Self {
                addr,
                target_rx: Mutex::new(target_rx),
                chunk_rx: Mutex::new(chunk_rx),
                send_tx,
                _accepted: accepted,
            }
        }

        fn url(&self) -> Url {
            Url::parse(&format!("ws://{}/tcp", self.addr)).unwrap()
        }

        async fn expect_target(&self) -> Vec<u8> {
            tokio::time::timeout(Duration::from_secs(2), async {
                self.target_rx.lock().await.recv().await
            })
            .await
            .unwrap()
            .unwrap()
        }

        async fn recv_chunk(&self) -> Vec<u8> {
            tokio::time::timeout(Duration::from_secs(2), async {
                self.chunk_rx.lock().await.recv().await
            })
            .await
            .unwrap()
            .unwrap()
        }

        async fn try_recv_chunk(&self) -> Option<Vec<u8>> {
            tokio::time::timeout(Duration::from_millis(100), async {
                self.chunk_rx.lock().await.recv().await
            })
            .await
            .ok()
            .flatten()
        }

        async fn send_chunk(&self, data: &[u8]) {
            self.send_tx.send(data.to_vec()).unwrap();
        }

        async fn close(&self) {
            let _ = self.send_tx.send(Vec::new());
        }
    }

    async fn handle_test_tcp_upstream(
        stream: TcpStream,
        target_tx: mpsc::UnboundedSender<Vec<u8>>,
        chunk_tx: mpsc::UnboundedSender<Vec<u8>>,
        mut send_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ws = accept_async(MaybeTlsStream::Plain(stream)).await?;
        let ws = AnyWsStream::Http1 { inner: ws };
        let (sink, stream) = ws.split();
        let cipher = CipherKind::Chacha20IetfPoly1305;
        let master_key = cipher.derive_master_key("Secret0").unwrap();
        let lifetime = super::UpstreamTransportGuard::new("test", "tcp");
        let (mut writer, ctrl_tx) =
            TcpShadowsocksWriter::connect(sink, cipher, &master_key, Arc::clone(&lifetime)).await?;
        let request_salt = writer.request_salt().map(|salt| salt.to_vec());
        let mut reader = TcpShadowsocksReader::new(stream, cipher, &master_key, lifetime, ctrl_tx)
            .with_request_salt(request_salt);

        target_tx.send(reader.read_chunk().await?).unwrap();

        loop {
            tokio::select! {
                inbound = reader.read_chunk() => {
                    match inbound {
                        Ok(chunk) => {
                            chunk_tx.send(chunk).unwrap();
                        }
                        Err(_) => break,
                    }
                }
                outbound = send_rx.recv() => {
                    match outbound {
                        Some(chunk) if chunk.is_empty() => break,
                        Some(chunk) => writer.send_chunk(&chunk).await?,
                        None => break,
                    }
                }
            }
        }

        Ok(())
    }
}
