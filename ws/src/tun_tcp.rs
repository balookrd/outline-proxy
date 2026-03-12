use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::config::TunTcpConfig;
use crate::metrics;
use crate::transport::{TcpShadowsocksReader, TcpShadowsocksWriter};
use crate::tun::SharedTunWriter;
use crate::types::TargetAddr;
use crate::uplink::{TransportKind, UplinkCandidate, UplinkManager};

pub(crate) const IPV4_HEADER_LEN: usize = 20;
pub(crate) const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
pub(crate) const TCP_FLAG_FIN: u8 = 0x01;
pub(crate) const TCP_FLAG_SYN: u8 = 0x02;
pub(crate) const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
pub(crate) const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
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

#[derive(Clone)]
pub struct TunTcpEngine {
    inner: Arc<TunTcpEngineInner>,
}

struct TunTcpEngineInner {
    writer: SharedTunWriter,
    uplinks: UplinkManager,
    flows: Mutex<HashMap<TcpFlowKey, Arc<Mutex<TcpFlowState>>>>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpFlowStatus {
    SynReceived,
    Established,
    ClientClosed,
    ServerClosed,
    Closed,
}

struct TcpFlowState {
    id: u64,
    key: TcpFlowKey,
    uplink_index: usize,
    uplink_name: String,
    upstream_writer: Arc<Mutex<TcpShadowsocksWriter>>,
    status: TcpFlowStatus,
    client_next_seq: u32,
    client_window_scale: u8,
    client_sack_permitted: bool,
    client_window: u32,
    client_window_end: u32,
    client_window_update_seq: u32,
    client_window_update_ack: u32,
    server_seq: u32,
    last_client_ack: u32,
    duplicate_ack_count: u8,
    receive_window_capacity: usize,
    smoothed_rtt: Option<Duration>,
    rttvar: Duration,
    retransmission_timeout: Duration,
    congestion_window: usize,
    slow_start_threshold: usize,
    pending_server_data: VecDeque<Vec<u8>>,
    unacked_server_segments: VecDeque<ServerSegment>,
    pending_client_segments: Vec<BufferedClientSegment>,
    server_fin_pending: bool,
    zero_window_probe_backoff: Duration,
    next_zero_window_probe_at: Option<Instant>,
    reported_inflight_segments: usize,
    reported_inflight_bytes: usize,
    reported_pending_server_bytes: usize,
    reported_buffered_client_segments: usize,
    reported_zero_window: bool,
    reported_active: bool,
    reported_congestion_window: usize,
    reported_slow_start_threshold: usize,
    reported_retransmission_timeout_us: u64,
    reported_smoothed_rtt_us: u64,
    created_at: Instant,
    status_since: Instant,
    last_seen: Instant,
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
    window_scale: Option<u8>,
    sack_permitted: bool,
    sack_blocks: Vec<(u32, u32)>,
    flags: u8,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct ClientSegmentView {
    payload: Vec<u8>,
    fin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BufferedClientSegment {
    sequence_number: u32,
    flags: u8,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ServerSegment {
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    payload: Vec<u8>,
    sacked: bool,
    last_sent: Instant,
    first_sent: Instant,
    retransmits: u32,
}

#[derive(Debug, Default)]
struct ServerFlush {
    data_packets: Vec<Vec<u8>>,
    fin_packet: Option<Vec<u8>>,
    probe_packet: Option<Vec<u8>>,
    window_stalled: bool,
}

#[derive(Debug, Default)]
struct ParsedTcpOptions {
    window_scale: Option<u8>,
    sack_permitted: bool,
    sack_blocks: Vec<(u32, u32)>,
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
                next_flow_id: AtomicU64::new(1),
                max_flows,
                idle_timeout,
                tcp,
            }),
        };
        engine.spawn_cleanup_loop();
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

        if (parsed.flags & TCP_FLAG_RST) != 0 {
            self.close_flow(&key, "client_rst").await;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_rst_observed");
            return Ok(());
        }

        let flow = self.lookup_flow(&key).await;
        match flow {
            Some(flow) => self.handle_existing_flow(flow, parsed).await,
            None => self.handle_new_flow(key, parsed).await,
        }
    }

    fn spawn_cleanup_loop(&self) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(TCP_FLOW_CLEANUP_INTERVAL).await;
                engine.cleanup_idle_flows().await;
            }
        });
    }

    async fn lookup_flow(&self, key: &TcpFlowKey) -> Option<Arc<Mutex<TcpFlowState>>> {
        self.inner.flows.lock().await.get(key).cloned()
    }

    async fn abort_flow_with_rst(&self, key: &TcpFlowKey, reason: &'static str) {
        let flow = self.inner.flows.lock().await.remove(key);
        let Some(flow) = flow else {
            return;
        };

        let (flow_id, uplink_name, duration, upstream_writer, rst_packet) = {
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
                Arc::clone(&state.upstream_writer),
                rst_packet,
            )
        };

        if let Some(packet) = rst_packet {
            let _ = self.inner.writer.write_packet(&packet).await;
            metrics::record_tun_packet(
                "upstream_to_tun",
                ip_family_from_version(key.version),
                "tcp_rst",
            );
        }
        close_upstream_writer(upstream_writer).await;
        metrics::record_tun_flow_closed(&uplink_name, reason, duration);
        metrics::record_tun_tcp_event(&uplink_name, reason);
        debug!(flow_id, uplink = %uplink_name, reason, "aborted TUN TCP flow");
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

        let target = ip_to_target(key.remote_ip, key.remote_port);
        let (candidate, upstream_writer, upstream_reader) = match timeout(
            self.inner.tcp.connect_timeout,
            select_tcp_candidate_and_connect(&self.inner.uplinks, &target),
        )
        .await
        {
            Ok(Ok(connected)) => connected,
            Ok(Err(error)) => {
                warn!(remote = %target, error = %format!("{error:#}"), "failed to establish TUN TCP upstream");
                let reset = build_reset_response(&packet)?;
                self.inner.writer.write_packet(&reset).await?;
                metrics::record_tun_packet(
                    "upstream_to_tun",
                    ip_family_from_version(packet.version),
                    "tcp_rst",
                );
                return Ok(());
            }
            Err(_) => {
                warn!(remote = %target, timeout_secs = self.inner.tcp.connect_timeout.as_secs(), "timed out establishing TUN TCP upstream");
                let reset = build_reset_response(&packet)?;
                self.inner.writer.write_packet(&reset).await?;
                metrics::record_tun_packet(
                    "upstream_to_tun",
                    ip_family_from_version(packet.version),
                    "tcp_rst",
                );
                return Ok(());
            }
        };

        let server_isn = rand::random::<u32>();
        let flow_id = self.inner.next_flow_id.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        let state = Arc::new(Mutex::new(TcpFlowState {
            id: flow_id,
            key: key.clone(),
            uplink_index: candidate.index,
            uplink_name: candidate.uplink.name.clone(),
            upstream_writer: Arc::new(Mutex::new(upstream_writer)),
            status: TcpFlowStatus::SynReceived,
            client_next_seq: packet.sequence_number.wrapping_add(1),
            client_window_scale: packet.window_scale.unwrap_or(0),
            client_sack_permitted: packet.sack_permitted,
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
            receive_window_capacity: self.inner.tcp.max_buffered_client_bytes,
            smoothed_rtt: None,
            rttvar: TCP_INITIAL_RTO / 2,
            retransmission_timeout: TCP_INITIAL_RTO,
            congestion_window: MAX_SERVER_SEGMENT_PAYLOAD * TCP_INITIAL_CWND_SEGMENTS,
            slow_start_threshold: TCP_SERVER_RECV_WINDOW_CAPACITY,
            pending_server_data: VecDeque::new(),
            unacked_server_segments: VecDeque::new(),
            pending_client_segments: Vec::new(),
            server_fin_pending: false,
            zero_window_probe_backoff: TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL,
            next_zero_window_probe_at: None,
            reported_inflight_segments: 0,
            reported_inflight_bytes: 0,
            reported_pending_server_bytes: 0,
            reported_buffered_client_segments: 0,
            reported_zero_window: false,
            reported_active: false,
            reported_congestion_window: 0,
            reported_slow_start_threshold: 0,
            reported_retransmission_timeout_us: 0,
            reported_smoothed_rtt_us: 0,
            created_at: now,
            status_since: now,
            last_seen: now,
        }));

        self.insert_flow(key.clone(), Arc::clone(&state)).await?;
        self.spawn_upstream_reader(key.clone(), state.clone(), upstream_reader);

        let syn_ack = {
            let mut state = state.lock().await;
            sync_flow_metrics(&mut state);
            build_flow_syn_ack_packet(&state, server_isn, packet.sequence_number.wrapping_add(1))?
        };
        self.inner.writer.write_packet(&syn_ack).await?;
        metrics::record_tun_packet(
            "upstream_to_tun",
            ip_family_from_version(packet.version),
            "tcp_synack",
        );
        metrics::record_uplink_selected("tcp", &candidate.uplink.name);
        info!(
            flow_id,
            uplink = %candidate.uplink.name,
            remote = %target,
            "created TUN TCP flow"
        );
        Ok(())
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
        metrics::record_tun_flow_created(&uplink_name);
        metrics::record_tun_tcp_event(&uplink_name, "flow_created");

        Ok(())
    }

    async fn handle_existing_flow(
        &self,
        flow: Arc<Mutex<TcpFlowState>>,
        packet: ParsedTcpPacket,
    ) -> Result<()> {
        let ip_family = ip_family_from_version(packet.version);
        let mut state = flow.lock().await;
        state.last_seen = Instant::now();
        update_client_send_window(&mut state, &packet);
        if state.client_window > 0 {
            reset_zero_window_persist(&mut state);
        }
        sync_flow_metrics(&mut state);

        if state.status == TcpFlowStatus::SynReceived {
            if is_duplicate_syn(&packet, state.client_next_seq) {
                metrics::record_tun_tcp_event(&state.uplink_name, "duplicate_syn");
                let syn_ack = build_flow_syn_ack_packet(
                    &state,
                    state.server_seq.wrapping_sub(1),
                    state.client_next_seq,
                )?;
                drop(state);
                self.inner.writer.write_packet(&syn_ack).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_synack");
                return Ok(());
            }

            if (packet.flags & TCP_FLAG_ACK) != 0
                && packet.acknowledgement_number == state.server_seq
                && packet.sequence_number == state.client_next_seq
            {
                set_flow_status(&mut state, TcpFlowStatus::Established);
            } else {
                let syn_ack = build_flow_syn_ack_packet(
                    &state,
                    state.server_seq.wrapping_sub(1),
                    state.client_next_seq,
                )?;
                drop(state);
                self.inner.writer.write_packet(&syn_ack).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_synack");
                return Ok(());
            }
        }

        let ack_effect = process_server_ack(
            &mut state,
            packet.acknowledgement_number,
            &packet.sack_blocks,
        );
        if let AckEffect::Advanced {
            bytes_acked,
            rtt_sample,
        } = ack_effect
        {
            note_ack_progress(&mut state, bytes_acked, rtt_sample);
        }

        if (packet.flags & TCP_FLAG_ACK) != 0
            && state.status == TcpFlowStatus::ServerClosed
            && packet.acknowledgement_number >= state.server_seq
        {
            let key = state.key.clone();
            drop(state);
            self.close_flow(&key, "server_closed_acked").await;
            return Ok(());
        }

        if matches!(ack_effect, AckEffect::DuplicateThresholdReached) {
            note_congestion_event(&mut state, false);
            metrics::record_tun_tcp_event(&state.uplink_name, "fast_retransmit");
            if let Some(packet) = retransmit_oldest_unacked_packet(&mut state)? {
                if retransmit_budget_exhausted(&state, &self.inner.tcp) {
                    let key = state.key.clone();
                    drop(state);
                    self.abort_flow_with_rst(&key, "retransmit_budget_exhausted")
                        .await;
                    return Ok(());
                }
                sync_flow_metrics(&mut state);
                drop(state);
                self.inner.writer.write_packet(&packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_retransmit");
                return Ok(());
            }
        }

        if state.status == TcpFlowStatus::ServerClosed
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
            drop(state);
            self.inner.writer.write_packet(&fin_ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_fin");
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
            sync_flow_metrics(&mut state);
            let ack = build_flow_ack_packet(
                &state,
                state.server_seq,
                state.client_next_seq,
                TCP_FLAG_ACK,
            )?;
            drop(state);
            self.inner.writer.write_packet(&ack).await?;
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
            drop(state);
            self.inner.writer.write_packet(&ack).await?;
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
        let upstream_writer = Arc::clone(&state.upstream_writer);
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
            sync_flow_metrics(&mut state);
        } else if (packet.flags & TCP_FLAG_ACK) != 0 && packet.payload.is_empty() {
            let flush = flush_server_output(&mut state)?;
            sync_flow_metrics(&mut state);
            drop(state);
            if flush.window_stalled {
                metrics::record_tun_tcp_event(&key_uplink_name(&flow).await, "window_stall");
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_stall");
            }
            for packet in flush.data_packets {
                self.inner.writer.write_packet(&packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_data");
            }
            if let Some(packet) = flush.probe_packet {
                self.inner.writer.write_packet(&packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_probe");
            }
            if let Some(packet) = flush.fin_packet {
                self.inner.writer.write_packet(&packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_fin");
            }
            return Ok(());
        }

        let flush = flush_server_output(&mut state)?;
        sync_flow_metrics(&mut state);

        drop(state);

        if !pending_payload.is_empty() {
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
            metrics::add_bytes("tcp", "client_to_upstream", pending_payload.len());
            should_send_ack = true;
        }

        if should_send_ack {
            let ack = {
                let state = flow.lock().await;
                build_flow_ack_packet(&state, seq_number, ack_number, TCP_FLAG_ACK)?
            };
            self.inner.writer.write_packet(&ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
        }

        if flush.window_stalled {
            metrics::record_tun_tcp_event(&key_uplink_name(&flow).await, "window_stall");
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_stall");
        }
        for packet in flush.data_packets {
            self.inner.writer.write_packet(&packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_data");
        }
        if let Some(packet) = flush.probe_packet {
            metrics::record_tun_tcp_event(&key_uplink_name(&flow).await, "zero_window_probe");
            self.inner.writer.write_packet(&packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_window_probe");
        }
        if let Some(packet) = flush.fin_packet {
            metrics::record_tun_tcp_event(&key_uplink_name(&flow).await, "deferred_fin_sent");
            self.inner.writer.write_packet(&packet).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_fin");
        }

        if should_close_client_half {
            let should_close = {
                let mut state = flow.lock().await;
                let should_close = state.status == TcpFlowStatus::ServerClosed;
                set_flow_status(
                    &mut state,
                    if should_close {
                        TcpFlowStatus::Closed
                    } else {
                        TcpFlowStatus::ClientClosed
                    },
                );
                sync_flow_metrics(&mut state);
                should_close
            };
            close_upstream_writer(upstream_writer).await;
            if should_close {
                self.close_flow(&key, "fin_exchange_complete").await;
            }
        }

        Ok(())
    }

    fn spawn_upstream_reader(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        mut upstream_reader: TcpShadowsocksReader,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                match upstream_reader.read_chunk().await {
                    Ok(chunk) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        let (flush, ip_family, backlog_exceeded) = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.last_seen = Instant::now();
                            state.pending_server_data.push_back(chunk.clone());
                            let backlog_exceeded =
                                exceeds_server_backlog_limit(&state, &engine.inner.tcp);
                            let flush = flush_server_output(&mut state);
                            sync_flow_metrics(&mut state);
                            (flush, ip_family_from_version(key.version), backlog_exceeded)
                        };

                        if backlog_exceeded {
                            let uplink_name = key_uplink_name(&flow).await;
                            warn!(uplink = %uplink_name, "closing TUN TCP flow after server backlog limit");
                            engine
                                .abort_flow_with_rst(&key, "server_backlog_limit")
                                .await;
                            return;
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
                                metrics::add_bytes("tcp", "upstream_to_client", chunk.len());
                            }
                            Err(error) => {
                                warn!(error = %format!("{error:#}"), "failed to build TUN TCP data packet");
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        debug!(error = %format!("{error:#}"), "upstream TCP flow reader ended");
                        let flush = {
                            let mut state = flow.lock().await;
                            if matches!(
                                state.status,
                                TcpFlowStatus::Closed | TcpFlowStatus::ServerClosed
                            ) {
                                Ok(ServerFlush::default())
                            } else {
                                state.server_fin_pending = true;
                                flush_server_output(&mut state)
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
            let (flow_id, uplink_name, duration, upstream_writer) = {
                let mut state = flow.lock().await;
                set_flow_status(&mut state, TcpFlowStatus::Closed);
                clear_flow_metrics(&mut state);
                (
                    state.id,
                    state.uplink_name.clone(),
                    state.created_at.elapsed(),
                    Arc::clone(&state.upstream_writer),
                )
            };
            close_upstream_writer(upstream_writer).await;
            metrics::record_tun_flow_closed(&uplink_name, reason, duration);
            metrics::record_tun_tcp_event(&uplink_name, reason);
            debug!(flow_id, uplink = %uplink_name, reason, "closed TUN TCP flow");
        }
    }

    async fn cleanup_idle_flows(&self) {
        let cutoff = Instant::now() - self.inner.idle_timeout;
        let flows = {
            let guard = self.inner.flows.lock().await;
            guard
                .iter()
                .map(|(key, flow)| (key.clone(), Arc::clone(flow)))
                .collect::<Vec<_>>()
        };
        let mut expired = Vec::new();
        for (key, flow) in flows {
            let state = flow.lock().await;
            let handshake_expired = state.status == TcpFlowStatus::SynReceived
                && state.status_since.elapsed() >= self.inner.tcp.handshake_timeout;
            let half_close_expired = matches!(
                state.status,
                TcpFlowStatus::ClientClosed | TcpFlowStatus::ServerClosed
            ) && state.status_since.elapsed()
                >= self.inner.tcp.half_close_timeout;
            let idle_expired = state.last_seen <= cutoff;
            drop(state);
            if handshake_expired || half_close_expired || idle_expired {
                expired.push(key);
            }
        }

        for key in expired {
            let reason = if let Some(flow) = self.lookup_flow(&key).await {
                let state = flow.lock().await;
                if state.status == TcpFlowStatus::SynReceived
                    && state.status_since.elapsed() >= self.inner.tcp.handshake_timeout
                {
                    "handshake_timeout"
                } else if matches!(
                    state.status,
                    TcpFlowStatus::ClientClosed | TcpFlowStatus::ServerClosed
                ) && state.status_since.elapsed() >= self.inner.tcp.half_close_timeout
                {
                    "half_close_timeout"
                } else {
                    "idle_timeout"
                }
            } else {
                continue;
            };
            self.abort_flow_with_rst(&key, reason).await;
        }

        let flows = {
            let guard = self.inner.flows.lock().await;
            guard
                .iter()
                .map(|(key, flow)| (key.clone(), Arc::clone(flow)))
                .collect::<Vec<_>>()
        };
        for (key, flow) in flows {
            let packet_result = {
                let mut state = flow.lock().await;
                match retransmit_due_segment(&mut state) {
                    Ok(Some(packet)) => {
                        note_congestion_event(&mut state, true);
                        sync_flow_metrics(&mut state);
                        Ok(Some((packet, "tcp_retransmit")))
                    }
                    Ok(None) => match maybe_emit_zero_window_probe(&mut state) {
                        Ok(Some(packet)) => {
                            sync_flow_metrics(&mut state);
                            Ok(Some((packet, "tcp_window_probe")))
                        }
                        Ok(None) => Ok(None),
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                }
            };
            let packet = match packet_result {
                Ok(packet) => packet,
                Err(error) => {
                    warn!(error = %format!("{error:#}"), "failed to build retransmitted TUN TCP packet");
                    self.abort_flow_with_rst(&key, "retransmit_build_error")
                        .await;
                    continue;
                }
            };
            if let Some((packet, outcome)) = packet {
                if let Some(flow) = self.lookup_flow(&key).await {
                    let state = flow.lock().await;
                    if retransmit_budget_exhausted(&state, &self.inner.tcp) {
                        drop(state);
                        self.abort_flow_with_rst(&key, "retransmit_budget_exhausted")
                            .await;
                        continue;
                    }
                }
                let ip_family = ip_family_from_version(key.version);
                if let Err(error) = self.inner.writer.write_packet(&packet).await {
                    warn!(error = %format!("{error:#}"), "failed to retransmit TUN TCP packet");
                    self.close_flow(&key, "write_tun_error").await;
                } else {
                    let uplink_name = key_uplink_name(&flow).await;
                    metrics::record_tun_tcp_event(
                        &uplink_name,
                        if outcome == "tcp_retransmit" {
                            "timeout_retransmit"
                        } else {
                            "zero_window_probe"
                        },
                    );
                    metrics::record_tun_packet("upstream_to_tun", ip_family, outcome);
                }
            }
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
}

async fn close_upstream_writer(upstream_writer: Arc<Mutex<TcpShadowsocksWriter>>) {
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
    for candidate in uplinks.tcp_candidates(target).await {
        match connect_tcp_uplink(uplinks, &candidate, target).await {
            Ok((writer, reader)) => {
                return Ok((candidate, writer, reader));
            }
            Err(error) => {
                uplinks
                    .report_runtime_failure(candidate.index, TransportKind::Tcp, &error)
                    .await;
                last_error = Some(format!("{}: {error:#}", candidate.uplink.name));
            }
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
    let ws_stream = uplinks.acquire_tcp_standby_or_connect(candidate).await?;
    let (ws_sink, ws_stream) = ws_stream.split();

    let uplink = &candidate.uplink;
    let master_key = uplink.cipher.derive_master_key(&uplink.password);
    let mut writer = TcpShadowsocksWriter::connect(ws_sink, uplink.cipher, &master_key).await?;
    let reader = TcpShadowsocksReader::new(ws_stream, uplink.cipher, &master_key);
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
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if (fragment_field & 0x1fff) != 0 || (fragment_field & 0x2000) != 0 {
        bail!("IPv4 fragments are not supported on TUN TCP path");
    }
    if packet[9] != 6 {
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
    if packet[6] != 6 {
        bail!("IPv6 extension headers are not supported on TUN TCP path");
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&packet[24..40]);
    parse_tcp_segment(
        IpVersion::V6,
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        &packet[IPV6_HEADER_LEN..total_len],
    )
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
        window_scale: options.window_scale,
        sack_permitted: options.sack_permitted,
        sack_blocks: options.sack_blocks,
        flags: segment[13],
        payload: segment[header_len..].to_vec(),
    })
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

fn build_flow_packet(
    state: &TcpFlowState,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    build_flow_packet_with_options(
        state,
        sequence_number,
        acknowledgement_number,
        flags,
        &[],
        payload,
    )
}

fn build_flow_packet_with_options(
    state: &TcpFlowState,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    build_response_packet_custom(
        state.key.version,
        state.key.remote_ip,
        state.key.client_ip,
        state.key.remote_port,
        state.key.client_port,
        sequence_number,
        acknowledgement_number,
        flags,
        advertised_receive_window(state),
        options,
        payload,
    )
}

fn build_flow_ack_packet(
    state: &TcpFlowState,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
) -> Result<Vec<u8>> {
    let options = ack_options(state);
    build_flow_packet_with_options(
        state,
        sequence_number,
        acknowledgement_number,
        flags,
        &options,
        &[],
    )
}

fn build_flow_syn_ack_packet(
    state: &TcpFlowState,
    server_isn: u32,
    acknowledgement_number: u32,
) -> Result<Vec<u8>> {
    build_response_packet_custom(
        state.key.version,
        state.key.remote_ip,
        state.key.client_ip,
        state.key.remote_port,
        state.key.client_port,
        server_isn,
        acknowledgement_number,
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        advertised_receive_window(state),
        &syn_ack_options(state.client_sack_permitted),
        &[],
    )
}

fn syn_ack_options(client_sack_permitted: bool) -> Vec<u8> {
    let mut options = Vec::new();
    if client_sack_permitted {
        options.extend_from_slice(&[1, 1, 4, 2]);
    }
    options.extend_from_slice(&[1, 3, 3, TCP_SERVER_WINDOW_SCALE]);
    while options.len() % 4 != 0 {
        options.push(1);
    }
    options
}

fn ack_options(state: &TcpFlowState) -> Vec<u8> {
    if !state.client_sack_permitted {
        return Vec::new();
    }

    let mut ranges = state
        .pending_client_segments
        .iter()
        .filter_map(|segment| {
            if !seq_gt(segment.sequence_number, state.client_next_seq) {
                return None;
            }
            Some((
                segment.sequence_number,
                segment
                    .sequence_number
                    .wrapping_add(segment.payload.len() as u32),
            ))
        })
        .collect::<Vec<_>>();
    if ranges.is_empty() {
        return Vec::new();
    }

    ranges.sort_by(|(left_a, _), (left_b, _)| left_a.cmp(left_b));
    let mut merged = Vec::new();
    for (left, right) in ranges {
        match merged.last_mut() {
            Some((_, merged_right)) if !seq_gt(left, *merged_right) => {
                if seq_gt(right, *merged_right) {
                    *merged_right = right;
                }
            }
            _ => merged.push((left, right)),
        }
    }

    let mut options = Vec::new();
    let block_count = merged.len().min(4);
    options.push(5);
    options.push((2 + block_count * 8) as u8);
    for (left, right) in merged.into_iter().take(block_count) {
        options.extend_from_slice(&left.to_be_bytes());
        options.extend_from_slice(&right.to_be_bytes());
    }
    while options.len() % 4 != 0 {
        options.push(1);
    }
    options
}

fn advertised_receive_window(state: &TcpFlowState) -> u16 {
    let buffered_bytes = buffered_client_bytes(state);
    let available = state.receive_window_capacity.saturating_sub(buffered_bytes);
    let scaled = available >> TCP_SERVER_WINDOW_SCALE;
    scaled.min(u16::MAX as usize) as u16
}

fn decode_client_window(packet: &ParsedTcpPacket, scale: u8) -> u32 {
    if (packet.flags & TCP_FLAG_SYN) != 0 {
        u32::from(packet.window_size)
    } else {
        u32::from(packet.window_size) << scale.min(14)
    }
}

fn update_client_send_window(state: &mut TcpFlowState, packet: &ParsedTcpPacket) {
    let decoded_window = decode_client_window(packet, state.client_window_scale);
    let should_update = seq_gt(packet.sequence_number, state.client_window_update_seq)
        || (packet.sequence_number == state.client_window_update_seq
            && (seq_gt(
                packet.acknowledgement_number,
                state.client_window_update_ack,
            ) || (packet.acknowledgement_number == state.client_window_update_ack
                && decoded_window > state.client_window)));
    if should_update || decoded_window == 0 {
        state.client_window = decoded_window;
        state.client_window_end = packet.acknowledgement_number.wrapping_add(decoded_window);
        state.client_window_update_seq = packet.sequence_number;
        state.client_window_update_ack = packet.acknowledgement_number;
    }
}

fn send_window_remaining(state: &TcpFlowState) -> u32 {
    if seq_ge(state.server_seq, state.client_window_end) {
        0
    } else {
        state.client_window_end.wrapping_sub(state.server_seq)
    }
}

fn buffered_client_bytes(state: &TcpFlowState) -> usize {
    state
        .pending_client_segments
        .iter()
        .map(|segment| segment.payload.len())
        .sum()
}

fn set_flow_status(state: &mut TcpFlowState, status: TcpFlowStatus) {
    if state.status != status {
        state.status = status;
        state.status_since = Instant::now();
    }
}

fn reset_zero_window_persist(state: &mut TcpFlowState) {
    state.zero_window_probe_backoff = TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL;
    state.next_zero_window_probe_at = None;
}

fn receive_window_end(state: &TcpFlowState) -> u32 {
    state.client_next_seq.wrapping_add(
        state
            .receive_window_capacity
            .saturating_sub(buffered_client_bytes(state)) as u32,
    )
}

fn trim_packet_to_receive_window(
    state: &TcpFlowState,
    packet: &ParsedTcpPacket,
) -> Option<ParsedTcpPacket> {
    if packet.payload.is_empty() && (packet.flags & TCP_FLAG_FIN) == 0 {
        return Some(packet.clone());
    }

    let recv_window_end = receive_window_end(state);
    if seq_ge(packet.sequence_number, recv_window_end) {
        return None;
    }

    let mut trimmed = packet.clone();
    if !trimmed.payload.is_empty() {
        let allowed_len = recv_window_end.wrapping_sub(trimmed.sequence_number) as usize;
        if trimmed.payload.len() > allowed_len {
            trimmed.payload.truncate(allowed_len);
            trimmed.flags &= !TCP_FLAG_FIN;
        }
    }
    Some(trimmed)
}

fn normalize_client_segment(packet: &ParsedTcpPacket, expected_seq: u32) -> ClientSegmentView {
    normalize_client_segment_parts(
        packet.sequence_number,
        packet.flags,
        &packet.payload,
        expected_seq,
    )
}

fn normalize_client_segment_parts(
    sequence_number: u32,
    flags: u8,
    payload: &[u8],
    expected_seq: u32,
) -> ClientSegmentView {
    let original_payload_len = payload.len();
    let overlap = if seq_lt(sequence_number, expected_seq) {
        expected_seq.wrapping_sub(sequence_number) as usize
    } else {
        0
    };

    let payload = if overlap >= payload.len() {
        Vec::new()
    } else {
        payload[overlap..].to_vec()
    };

    let fin = if (flags & TCP_FLAG_FIN) == 0 {
        false
    } else {
        overlap <= original_payload_len
    };

    ClientSegmentView { payload, fin }
}

fn queue_future_segment(
    pending_segments: &mut Vec<BufferedClientSegment>,
    packet: &ParsedTcpPacket,
) {
    if packet.payload.is_empty() && (packet.flags & TCP_FLAG_FIN) == 0 {
        return;
    }
    let candidate = BufferedClientSegment {
        sequence_number: packet.sequence_number,
        flags: packet.flags & (TCP_FLAG_FIN | TCP_FLAG_ACK),
        payload: packet.payload.clone(),
    };
    if pending_segments
        .iter()
        .any(|existing| existing == &candidate)
    {
        return;
    }
    pending_segments.push(candidate);
}

fn queue_future_segment_with_recv_window(state: &mut TcpFlowState, packet: &ParsedTcpPacket) {
    let Some(trimmed) = trim_packet_to_receive_window(state, packet) else {
        return;
    };
    queue_future_segment(&mut state.pending_client_segments, &trimmed);
}

fn exceeds_client_reassembly_limits(state: &TcpFlowState, config: &TunTcpConfig) -> bool {
    state.pending_client_segments.len() > config.max_buffered_client_segments
        || buffered_client_bytes(state) > config.max_buffered_client_bytes
}

fn exceeds_server_backlog_limit(state: &TcpFlowState, config: &TunTcpConfig) -> bool {
    pending_server_bytes(state) > config.max_pending_server_bytes
}

fn retransmit_budget_exhausted(state: &TcpFlowState, config: &TunTcpConfig) -> bool {
    state
        .unacked_server_segments
        .iter()
        .any(|segment| segment.retransmits >= config.max_retransmits)
}

fn drain_ready_buffered_segments(
    expected_seq: &mut u32,
    pending_segments: &mut Vec<BufferedClientSegment>,
    pending_payload: &mut Vec<u8>,
) -> bool {
    loop {
        let Some(index) = find_next_ready_segment_index(*expected_seq, pending_segments) else {
            return false;
        };
        let segment = pending_segments.remove(index);
        let normalized = normalize_client_segment_parts(
            segment.sequence_number,
            segment.flags,
            &segment.payload,
            *expected_seq,
        );
        if normalized.payload.is_empty() && !normalized.fin {
            continue;
        }
        let mut should_close_client_half = false;
        if apply_client_segment(
            expected_seq,
            normalized,
            pending_payload,
            &mut should_close_client_half,
        ) {
            return true;
        }
    }
}

fn drain_ready_buffered_segments_from_state(
    state: &mut TcpFlowState,
    pending_payload: &mut Vec<u8>,
) -> bool {
    drain_ready_buffered_segments(
        &mut state.client_next_seq,
        &mut state.pending_client_segments,
        pending_payload,
    )
}

fn apply_client_segment(
    expected_seq: &mut u32,
    segment: ClientSegmentView,
    pending_payload: &mut Vec<u8>,
    should_close_client_half: &mut bool,
) -> bool {
    if !segment.payload.is_empty() {
        *expected_seq = expected_seq.wrapping_add(segment.payload.len() as u32);
        pending_payload.extend_from_slice(&segment.payload);
    }
    if segment.fin {
        *expected_seq = expected_seq.wrapping_add(1);
        *should_close_client_half = true;
        return true;
    }
    false
}

fn find_next_ready_segment_index(
    expected_seq: u32,
    pending_segments: &[BufferedClientSegment],
) -> Option<usize> {
    let mut best: Option<(usize, u32)> = None;
    for (index, segment) in pending_segments.iter().enumerate() {
        if seq_gt(segment.sequence_number, expected_seq) {
            continue;
        }
        if best
            .as_ref()
            .map(|(_, best_seq)| seq_lt(segment.sequence_number, *best_seq))
            .unwrap_or(true)
        {
            best = Some((index, segment.sequence_number));
        }
    }
    best.map(|(index, _)| index)
}

fn is_duplicate_syn(packet: &ParsedTcpPacket, expected_seq: u32) -> bool {
    (packet.flags & TCP_FLAG_SYN) != 0
        && (packet.flags & TCP_FLAG_ACK) == 0
        && packet.payload.is_empty()
        && packet.sequence_number == expected_seq.wrapping_sub(1)
}

fn seq_lt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) < 0
}

fn seq_gt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) > 0
}

fn seq_ge(lhs: u32, rhs: u32) -> bool {
    !seq_lt(lhs, rhs)
}

fn seq_le(lhs: u32, rhs: u32) -> bool {
    !seq_gt(lhs, rhs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckEffect {
    None,
    Advanced {
        bytes_acked: usize,
        rtt_sample: Option<Duration>,
    },
    Duplicate,
    DuplicateThresholdReached,
}

fn process_server_ack(
    state: &mut TcpFlowState,
    acknowledgement_number: u32,
    sack_blocks: &[(u32, u32)],
) -> AckEffect {
    if state.unacked_server_segments.is_empty() {
        state.last_client_ack = acknowledgement_number;
        state.duplicate_ack_count = 0;
        return AckEffect::None;
    }

    for segment in &mut state.unacked_server_segments {
        let segment_end = segment
            .sequence_number
            .wrapping_add(server_segment_len(segment) as u32);
        if sack_blocks.iter().any(|(left, right)| {
            seq_le(*left, segment.sequence_number) && seq_ge(*right, segment_end)
        }) {
            segment.sacked = true;
        }
    }

    if seq_gt(acknowledgement_number, state.last_client_ack) {
        state.last_client_ack = acknowledgement_number;
        state.duplicate_ack_count = 0;
        let mut bytes_acked = 0usize;
        let mut rtt_sample = None;
        while let Some(segment) = state.unacked_server_segments.front() {
            let segment_end = segment
                .sequence_number
                .wrapping_add(server_segment_len(segment) as u32);
            if seq_ge(acknowledgement_number, segment_end) {
                let segment = state
                    .unacked_server_segments
                    .pop_front()
                    .expect("front exists");
                bytes_acked = bytes_acked.saturating_add(server_segment_len(&segment));
                if segment.retransmits == 0 {
                    rtt_sample = Some(segment.first_sent.elapsed());
                }
            } else {
                break;
            }
        }
        AckEffect::Advanced {
            bytes_acked,
            rtt_sample,
        }
    } else if acknowledgement_number == state.last_client_ack {
        state.duplicate_ack_count = state.duplicate_ack_count.saturating_add(1);
        if state.duplicate_ack_count >= TCP_FAST_RETRANSMIT_DUP_ACKS {
            state.duplicate_ack_count = 0;
            AckEffect::DuplicateThresholdReached
        } else {
            AckEffect::Duplicate
        }
    } else {
        AckEffect::None
    }
}

fn highest_sacked_end(state: &TcpFlowState) -> Option<u32> {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| segment.sacked)
        .map(|segment| {
            segment
                .sequence_number
                .wrapping_add(server_segment_len(segment) as u32)
        })
        .max_by(|lhs, rhs| lhs.cmp(rhs))
}

fn preferred_retransmit_index(state: &TcpFlowState) -> Option<usize> {
    if let Some(highest_sacked_end) = highest_sacked_end(state) {
        if let Some(index) = state.unacked_server_segments.iter().position(|segment| {
            !segment.sacked && seq_lt(segment.sequence_number, highest_sacked_end)
        }) {
            return Some(index);
        }
    }

    state
        .unacked_server_segments
        .iter()
        .position(|segment| !segment.sacked)
        .or_else(|| (!state.unacked_server_segments.is_empty()).then_some(0))
}

fn congestion_window_remaining(state: &TcpFlowState) -> usize {
    state
        .congestion_window
        .saturating_sub(bytes_in_flight(&state.unacked_server_segments))
}

fn current_retransmission_timeout(state: &TcpFlowState) -> Duration {
    state.retransmission_timeout
}

fn update_rtt_estimator(state: &mut TcpFlowState, sample: Duration) {
    let sample_us = sample.as_micros() as f64;
    match state.smoothed_rtt {
        Some(smoothed_rtt) => {
            let srtt_us = smoothed_rtt.as_micros() as f64;
            let rttvar_us = state.rttvar.as_micros() as f64;
            let new_rttvar_us = 0.75 * rttvar_us + 0.25 * (srtt_us - sample_us).abs();
            let new_srtt_us = 0.875 * srtt_us + 0.125 * sample_us;
            state.smoothed_rtt = Some(Duration::from_micros(new_srtt_us.max(1.0) as u64));
            state.rttvar = Duration::from_micros(new_rttvar_us.max(1.0) as u64);
        }
        None => {
            state.smoothed_rtt = Some(sample);
            state.rttvar = sample / 2;
        }
    }

    let srtt = state.smoothed_rtt.unwrap_or(sample);
    let rto = srtt
        .saturating_add(state.rttvar.saturating_mul(4))
        .clamp(TCP_MIN_RTO, TCP_MAX_RTO);
    state.retransmission_timeout = rto;
}

fn note_ack_progress(state: &mut TcpFlowState, bytes_acked: usize, rtt_sample: Option<Duration>) {
    if let Some(sample) = rtt_sample {
        update_rtt_estimator(state, sample);
    }
    if bytes_acked == 0 {
        return;
    }

    if state.congestion_window < state.slow_start_threshold {
        state.congestion_window = state.congestion_window.saturating_add(bytes_acked);
    } else {
        let additive =
            ((MAX_SERVER_SEGMENT_PAYLOAD * bytes_acked) / state.congestion_window).max(1);
        state.congestion_window = state.congestion_window.saturating_add(additive);
    }
}

fn note_congestion_event(state: &mut TcpFlowState, timeout: bool) {
    let inflight = bytes_in_flight(&state.unacked_server_segments);
    state.slow_start_threshold = (inflight / 2).max(TCP_MIN_SSTHRESH);
    state.congestion_window = if timeout {
        MAX_SERVER_SEGMENT_PAYLOAD
    } else {
        state.slow_start_threshold
    };
    if timeout {
        state.retransmission_timeout = current_retransmission_timeout(state)
            .saturating_mul(2)
            .clamp(TCP_MIN_RTO, TCP_MAX_RTO);
    }
}

fn flush_server_data(state: &mut TcpFlowState) -> Result<Vec<Vec<u8>>> {
    let mut packets = Vec::new();
    let mut available_window =
        send_window_remaining(state).min(congestion_window_remaining(state) as u32);

    while available_window > 0 {
        let Some(front) = state.pending_server_data.front_mut() else {
            break;
        };
        if front.is_empty() {
            state.pending_server_data.pop_front();
            continue;
        }

        let payload_len = front
            .len()
            .min(MAX_SERVER_SEGMENT_PAYLOAD)
            .min(available_window as usize);
        let payload = front.drain(..payload_len).collect::<Vec<_>>();
        if front.is_empty() {
            state.pending_server_data.pop_front();
        }

        let sequence_number = state.server_seq;
        let acknowledgement_number = state.client_next_seq;
        let packet = build_flow_packet(
            state,
            sequence_number,
            acknowledgement_number,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            &payload,
        )?;
        state.server_seq = state.server_seq.wrapping_add(payload.len() as u32);
        state.unacked_server_segments.push_back(ServerSegment {
            sequence_number,
            acknowledgement_number,
            flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
            payload,
            sacked: false,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
        });
        reset_zero_window_persist(state);
        packets.push(packet);
        available_window =
            send_window_remaining(state).min(congestion_window_remaining(state) as u32);
    }

    Ok(packets)
}

fn flush_server_output(state: &mut TcpFlowState) -> Result<ServerFlush> {
    let data_packets = flush_server_data(state)?;
    let window_stalled = send_window_remaining(state) == 0 && !state.pending_server_data.is_empty();
    let fin_packet = maybe_emit_server_fin(state)?;
    let probe_packet = maybe_emit_zero_window_probe(state)?;
    Ok(ServerFlush {
        data_packets,
        fin_packet,
        probe_packet,
        window_stalled,
    })
}

fn maybe_emit_server_fin(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
    if !state.server_fin_pending
        || !state.pending_server_data.is_empty()
        || !state.unacked_server_segments.is_empty()
        || matches!(
            state.status,
            TcpFlowStatus::Closed | TcpFlowStatus::ServerClosed
        )
    {
        return Ok(None);
    }

    let packet = build_flow_packet(
        state,
        state.server_seq,
        state.client_next_seq,
        TCP_FLAG_FIN | TCP_FLAG_ACK,
        &[],
    )?;
    let sequence_number = state.server_seq;
    state.server_seq = state.server_seq.wrapping_add(1);
    state.server_fin_pending = false;
    set_flow_status(
        state,
        if state.status == TcpFlowStatus::ClientClosed {
            TcpFlowStatus::Closed
        } else {
            TcpFlowStatus::ServerClosed
        },
    );
    state.unacked_server_segments.push_back(ServerSegment {
        sequence_number,
        acknowledgement_number: state.client_next_seq,
        flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
        payload: Vec::new(),
        sacked: false,
        last_sent: Instant::now(),
        first_sent: Instant::now(),
        retransmits: 0,
    });
    Ok(Some(packet))
}

fn maybe_emit_zero_window_probe(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
    if send_window_remaining(state) != 0
        || state.pending_server_data.is_empty()
        || !state.unacked_server_segments.is_empty()
    {
        return Ok(None);
    }

    let now = Instant::now();
    if state
        .next_zero_window_probe_at
        .map(|deadline| deadline > now)
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let Some(front) = state.pending_server_data.front() else {
        return Ok(None);
    };
    let Some(&probe_byte) = front.first() else {
        return Ok(None);
    };
    let packet = build_flow_packet(
        state,
        state.server_seq,
        state.client_next_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        &[probe_byte],
    )?;
    let current = state.zero_window_probe_backoff;
    state.next_zero_window_probe_at = Some(now + current);
    state.zero_window_probe_backoff =
        (current.saturating_mul(2)).min(TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL);
    Ok(Some(packet))
}

fn retransmit_oldest_unacked_packet(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
    let index = preferred_retransmit_index(state);
    let Some(index) = index else {
        return Ok(None);
    };
    let (sequence_number, acknowledgement_number, flags, payload) = {
        let segment = &mut state.unacked_server_segments[index];
        segment.last_sent = Instant::now();
        segment.retransmits = segment.retransmits.saturating_add(1);
        (
            segment.sequence_number,
            segment.acknowledgement_number,
            segment.flags,
            segment.payload.clone(),
        )
    };
    Ok(Some(build_flow_packet(
        state,
        sequence_number,
        state.client_next_seq.max(acknowledgement_number),
        flags,
        &payload,
    )?))
}

fn retransmit_due_segment(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
    let Some(index) = preferred_retransmit_index(state)
        .filter(|index| {
            state.unacked_server_segments[*index].last_sent.elapsed()
                >= current_retransmission_timeout(state)
        })
        .or_else(|| {
            let rto = current_retransmission_timeout(state);
            state
                .unacked_server_segments
                .iter()
                .position(|segment| segment.last_sent.elapsed() >= rto)
        })
    else {
        return Ok(None);
    };
    let (sequence_number, acknowledgement_number, flags, payload) = {
        let segment = &mut state.unacked_server_segments[index];
        segment.last_sent = Instant::now();
        segment.retransmits = segment.retransmits.saturating_add(1);
        (
            segment.sequence_number,
            segment.acknowledgement_number,
            segment.flags,
            segment.payload.clone(),
        )
    };
    Ok(Some(build_flow_packet(
        state,
        sequence_number,
        state.client_next_seq.max(acknowledgement_number),
        flags,
        &payload,
    )?))
}

fn bytes_in_flight(segments: &VecDeque<ServerSegment>) -> usize {
    segments.iter().map(server_segment_len).sum()
}

fn server_segment_len(segment: &ServerSegment) -> usize {
    segment.payload.len()
        + usize::from((segment.flags & TCP_FLAG_SYN) != 0)
        + usize::from((segment.flags & TCP_FLAG_FIN) != 0)
}

fn pending_server_bytes(state: &TcpFlowState) -> usize {
    state.pending_server_data.iter().map(Vec::len).sum()
}

fn sync_flow_metrics(state: &mut TcpFlowState) {
    let inflight_segments = state.unacked_server_segments.len();
    let inflight_bytes = bytes_in_flight(&state.unacked_server_segments);
    let pending_server_bytes = pending_server_bytes(state);
    let buffered_client_segments = state.pending_client_segments.len();
    let zero_window = state.client_window == 0 && pending_server_bytes > 0;
    let congestion_window = state.congestion_window;
    let slow_start_threshold = state.slow_start_threshold;
    let retransmission_timeout_us = state.retransmission_timeout.as_micros() as u64;
    let smoothed_rtt_us = state
        .smoothed_rtt
        .map(|duration| duration.as_micros() as u64)
        .unwrap_or(0);

    let uplink = state.uplink_name.as_str();
    if !state.reported_active {
        metrics::add_tun_tcp_flows_active(uplink, 1);
        state.reported_active = true;
    }
    apply_usize_gauge_delta(
        uplink,
        inflight_segments,
        &mut state.reported_inflight_segments,
        metrics::add_tun_tcp_inflight_segments,
    );
    apply_usize_gauge_delta(
        uplink,
        inflight_bytes,
        &mut state.reported_inflight_bytes,
        metrics::add_tun_tcp_inflight_bytes,
    );
    apply_usize_gauge_delta(
        uplink,
        pending_server_bytes,
        &mut state.reported_pending_server_bytes,
        metrics::add_tun_tcp_pending_server_bytes,
    );
    apply_usize_gauge_delta(
        uplink,
        buffered_client_segments,
        &mut state.reported_buffered_client_segments,
        metrics::add_tun_tcp_buffered_client_segments,
    );
    if zero_window != state.reported_zero_window {
        metrics::add_tun_tcp_zero_window_flows(uplink, if zero_window { 1 } else { -1 });
        state.reported_zero_window = zero_window;
    }
    apply_usize_gauge_delta(
        uplink,
        congestion_window,
        &mut state.reported_congestion_window,
        metrics::add_tun_tcp_congestion_window_bytes,
    );
    apply_usize_gauge_delta(
        uplink,
        slow_start_threshold,
        &mut state.reported_slow_start_threshold,
        metrics::add_tun_tcp_slow_start_threshold_bytes,
    );
    apply_u64_seconds_gauge_delta(
        uplink,
        retransmission_timeout_us,
        &mut state.reported_retransmission_timeout_us,
        metrics::add_tun_tcp_retransmission_timeout_seconds,
    );
    apply_u64_seconds_gauge_delta(
        uplink,
        smoothed_rtt_us,
        &mut state.reported_smoothed_rtt_us,
        metrics::add_tun_tcp_smoothed_rtt_seconds,
    );
}

fn clear_flow_metrics(state: &mut TcpFlowState) {
    let uplink = state.uplink_name.as_str();
    if state.reported_active {
        metrics::add_tun_tcp_flows_active(uplink, -1);
        state.reported_active = false;
    }
    if state.reported_inflight_segments != 0 {
        metrics::add_tun_tcp_inflight_segments(uplink, -(state.reported_inflight_segments as i64));
        state.reported_inflight_segments = 0;
    }
    if state.reported_inflight_bytes != 0 {
        metrics::add_tun_tcp_inflight_bytes(uplink, -(state.reported_inflight_bytes as i64));
        state.reported_inflight_bytes = 0;
    }
    if state.reported_pending_server_bytes != 0 {
        metrics::add_tun_tcp_pending_server_bytes(
            uplink,
            -(state.reported_pending_server_bytes as i64),
        );
        state.reported_pending_server_bytes = 0;
    }
    if state.reported_buffered_client_segments != 0 {
        metrics::add_tun_tcp_buffered_client_segments(
            uplink,
            -(state.reported_buffered_client_segments as i64),
        );
        state.reported_buffered_client_segments = 0;
    }
    if state.reported_zero_window {
        metrics::add_tun_tcp_zero_window_flows(uplink, -1);
        state.reported_zero_window = false;
    }
    if state.reported_congestion_window != 0 {
        metrics::add_tun_tcp_congestion_window_bytes(
            uplink,
            -(state.reported_congestion_window as i64),
        );
        state.reported_congestion_window = 0;
    }
    if state.reported_slow_start_threshold != 0 {
        metrics::add_tun_tcp_slow_start_threshold_bytes(
            uplink,
            -(state.reported_slow_start_threshold as i64),
        );
        state.reported_slow_start_threshold = 0;
    }
    if state.reported_retransmission_timeout_us != 0 {
        metrics::add_tun_tcp_retransmission_timeout_seconds(
            uplink,
            -((state.reported_retransmission_timeout_us as f64) / 1_000_000.0),
        );
        state.reported_retransmission_timeout_us = 0;
    }
    if state.reported_smoothed_rtt_us != 0 {
        metrics::add_tun_tcp_smoothed_rtt_seconds(
            uplink,
            -((state.reported_smoothed_rtt_us as f64) / 1_000_000.0),
        );
        state.reported_smoothed_rtt_us = 0;
    }
}

fn apply_usize_gauge_delta(
    uplink: &str,
    current: usize,
    reported: &mut usize,
    record: fn(&str, i64),
) {
    let delta = current as i64 - *reported as i64;
    if delta != 0 {
        record(uplink, delta);
        *reported = current;
    }
}

fn apply_u64_seconds_gauge_delta(
    uplink: &str,
    current: u64,
    reported: &mut u64,
    record: fn(&str, f64),
) {
    let delta = current as f64 - *reported as f64;
    if delta != 0.0 {
        record(uplink, delta / 1_000_000.0);
        *reported = current;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, SocketAddr};
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
    use crate::types::{CipherKind, TargetAddr, WsTransportMode};
    use crate::uplink::UplinkManager;
    use futures_util::StreamExt;
    use tokio::fs::File;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Mutex, mpsc};
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

    #[test]
    fn ipv4_syn_generates_rst_ack() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8,
            0x9c, 0x40, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x40, 0x00, 0, 0, 0, 0,
        ];
        let response = parse_action_response(&packet);
        assert_eq!(response[9], 6);
        assert_eq!(response[IPV4_HEADER_LEN + 13], TCP_FLAG_RST | TCP_FLAG_ACK);
    }

    #[test]
    fn ipv6_ack_generates_rst() {
        let packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x9c, 0x40, 0x00, 0x50, 0, 0,
            0, 1, 0, 0, 0, 5, 0x50, 0x10, 0x40, 0x00, 0, 0, 0, 0,
        ];
        let response = parse_action_response(&packet);
        assert_eq!(response[6], 6);
        assert_eq!(response[IPV6_HEADER_LEN + 13], TCP_FLAG_RST);
    }

    #[test]
    fn rst_packets_are_ignored() {
        let packet = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8,
            0x9c, 0x40, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 5, 0x50, 0x14, 0x40, 0x00, 0, 0, 0, 0,
        ];
        assert!(handle_stateless_packet(&packet).unwrap().is_none());
    }

    #[test]
    fn parsed_tcp_packet_keeps_payload() {
        let packet = [
            0x45,
            0x00,
            0x00,
            0x2b,
            0x00,
            0x00,
            0x00,
            0x00,
            64,
            6,
            0,
            0,
            10,
            0,
            0,
            2,
            8,
            8,
            8,
            8,
            0x9c,
            0x40,
            0x00,
            0x50,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            5,
            0x50,
            TCP_FLAG_ACK,
            0x40,
            0x00,
            0,
            0,
            0,
            0,
            b'a',
            b'b',
            b'c',
        ];
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
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
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
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
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
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
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
            window_scale: Some(4),
            sack_permitted: true,
            sack_blocks: Vec::new(),
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
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
            flags: TCP_FLAG_ACK,
            payload: b"later".to_vec(),
        };
        let mut pending = Vec::new();

        queue_future_segment(&mut pending, &packet);
        queue_future_segment(&mut pending, &packet);

        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn drain_ready_buffered_segments_reassembles_contiguous_tail() {
        let mut expected_seq = 103;
        let mut pending = vec![
            BufferedClientSegment {
                sequence_number: 106,
                flags: TCP_FLAG_ACK,
                payload: b"ghi".to_vec(),
            },
            BufferedClientSegment {
                sequence_number: 103,
                flags: TCP_FLAG_ACK,
                payload: b"def".to_vec(),
            },
        ];
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
        let mut pending = vec![BufferedClientSegment {
            sequence_number: 106,
            flags: TCP_FLAG_ACK,
            payload: b"ghi".to_vec(),
        }];
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
        let mut pending = vec![BufferedClientSegment {
            sequence_number: 103,
            flags: TCP_FLAG_ACK | TCP_FLAG_FIN,
            payload: b"def".to_vec(),
        }];
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
                sacked: false,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                retransmits: 0,
            },
            super::ServerSegment {
                sequence_number: 1004,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"BBBB".to_vec(),
                sacked: false,
                last_sent: Instant::now(),
                first_sent: Instant::now(),
                retransmits: 0,
            },
        ]);

        let effect = super::process_server_ack(&mut state, 1000, &[(1004, 1008)]);
        assert_eq!(effect, super::AckEffect::Duplicate);
        assert!(!state.unacked_server_segments[0].sacked);
        assert!(state.unacked_server_segments[1].sacked);
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
            window_scale: None,
            sack_permitted: false,
            sack_blocks: Vec::new(),
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
        state.pending_client_segments = vec![
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
        ];
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
    async fn retransmit_prefers_unsacked_hole_before_sacked_tail() {
        let mut state = tcp_flow_state_for_tests().await;
        state.client_next_seq = 500;
        state.unacked_server_segments = VecDeque::from([
            super::ServerSegment {
                sequence_number: 1000,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"AAAA".to_vec(),
                sacked: false,
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 0,
            },
            super::ServerSegment {
                sequence_number: 1004,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"BBBB".to_vec(),
                sacked: true,
                last_sent: Instant::now() - Duration::from_secs(2),
                first_sent: Instant::now() - Duration::from_secs(2),
                retransmits: 0,
            },
            super::ServerSegment {
                sequence_number: 1008,
                acknowledgement_number: 500,
                flags: TCP_FLAG_ACK | super::TCP_FLAG_PSH,
                payload: b"CCCC".to_vec(),
                sacked: false,
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

        super::note_ack_progress(&mut state, 600, Some(Duration::from_millis(120)));
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
            sacked: false,
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
        state.pending_client_segments = vec![
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
        ];
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
        assert!(super::exceeds_server_backlog_limit(&state, &config));
    }

    async fn build_test_manager(tcp_ws_url: Url) -> UplinkManager {
        UplinkManager::new(
            vec![UplinkConfig {
                name: "test".to_string(),
                tcp_ws_url,
                tcp_ws_mode: WsTransportMode::Http1,
                udp_ws_url: None,
                udp_ws_mode: WsTransportMode::Http1,
                cipher: CipherKind::Chacha20IetfPoly1305,
                password: "Secret0".to_string(),
                weight: 1.0,
                fwmark: None,
            }],
            ProbeConfig {
                interval: Duration::from_secs(30),
                timeout: Duration::from_secs(5),
                max_concurrent: 2,
                max_dials: 1,
                ws: WsProbeConfig { enabled: false },
                http: None,
                dns: None,
            },
            LoadBalancingConfig {
                sticky_ttl: Duration::from_secs(300),
                hysteresis: Duration::from_millis(50),
                failure_cooldown: Duration::from_secs(10),
                warm_standby_tcp: 0,
                warm_standby_udp: 0,
                rtt_ewma_alpha: 0.3,
                failure_penalty: Duration::from_millis(500),
                failure_penalty_max: Duration::from_secs(30),
                failure_penalty_halflife: Duration::from_secs(60),
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
        let mut packet = super::build_response_packet_custom(
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
        .unwrap();
        let tcp_offset = IPV4_HEADER_LEN;
        let checksum = super::tcp_checksum_ipv4(client_ip, remote_ip, &packet[tcp_offset..]);
        packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&checksum.to_be_bytes());
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
        let master_key = cipher.derive_master_key("Secret0");
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
            upstream_writer: Arc::new(Mutex::new(
                TcpShadowsocksWriter::connect(sink, cipher, &master_key)
                    .await
                    .unwrap(),
            )),
            status: super::TcpFlowStatus::Established,
            client_next_seq: 100,
            client_window_scale: 0,
            client_sack_permitted: false,
            client_window: 4096,
            client_window_end: 5096,
            client_window_update_seq: 100,
            client_window_update_ack: 1000,
            server_seq: 1000,
            last_client_ack: 1000,
            duplicate_ack_count: 0,
            receive_window_capacity: 262_144,
            smoothed_rtt: None,
            rttvar: super::TCP_INITIAL_RTO / 2,
            retransmission_timeout: super::TCP_INITIAL_RTO,
            congestion_window: super::MAX_SERVER_SEGMENT_PAYLOAD * super::TCP_INITIAL_CWND_SEGMENTS,
            slow_start_threshold: super::TCP_SERVER_RECV_WINDOW_CAPACITY,
            pending_server_data: VecDeque::new(),
            unacked_server_segments: VecDeque::new(),
            pending_client_segments: Vec::new(),
            server_fin_pending: false,
            zero_window_probe_backoff: super::TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL,
            next_zero_window_probe_at: None,
            reported_inflight_segments: 0,
            reported_inflight_bytes: 0,
            reported_pending_server_bytes: 0,
            reported_buffered_client_segments: 0,
            reported_zero_window: false,
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
        let master_key = cipher.derive_master_key("Secret0");
        let mut writer = TcpShadowsocksWriter::connect(sink, cipher, &master_key).await?;
        let mut reader = TcpShadowsocksReader::new(stream, cipher, &master_key);

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
