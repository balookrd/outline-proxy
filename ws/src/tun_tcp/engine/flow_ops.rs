use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use anyhow::{Result, bail};
use tokio::sync::{Mutex, Notify, watch};
use tracing::debug;

use crate::memory::maybe_shrink_hash_map;
use crate::metrics;

use super::super::maintenance::sync_flow_metrics_and_wake;
use super::super::state_machine::{
    TcpFlowState, TcpFlowStatus, build_flow_packet, build_flow_syn_ack_packet, clear_flow_metrics,
    decode_client_window, set_flow_status,
};
use super::super::wire::{ParsedTcpPacket, build_reset_response};
use super::super::{
    MAX_SERVER_SEGMENT_PAYLOAD, TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN,
    TCP_INITIAL_CWND_SEGMENTS, TCP_INITIAL_RTO, TCP_SERVER_RECV_WINDOW_CAPACITY,
    TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL, TcpFlowKey,
};
use super::{TunTcpEngine, close_upstream_writer, ip_family_from_version, ip_to_target};
use crate::tun::TunRoute;

impl TunTcpEngine {
    pub(super) async fn handle_new_flow(
        &self,
        key: TcpFlowKey,
        packet: ParsedTcpPacket,
    ) -> Result<()> {
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
        let route = self.inner.dispatch.resolve(&target).await;
        let (manager, route) = match &route {
            TunRoute::Group { manager, .. } => (manager.clone(), route.clone()),
            TunRoute::Direct { .. } => {
                // For direct flows, use a dummy manager (default group); the
                // actual connect skips the uplink pipeline entirely.
                (self.inner.dispatch.default_group().clone(), route)
            },
            TunRoute::Drop { reason } => {
                let reset = build_reset_response(&packet)?;
                self.inner.writer.write_packet(&reset).await?;
                metrics::record_tun_packet(
                    "upstream_to_tun",
                    ip_family_from_version(packet.version),
                    "tcp_rst",
                );
                debug!(remote = %target, reason, "TUN TCP route: dropping flow");
                return Ok(());
            },
        };

        if !self.begin_pending_connect(key.clone()).await {
            debug!(remote = %target, "ignoring duplicate SYN while TUN TCP connect is already in progress");
            return Ok(());
        }

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
            manager: manager.clone(),
            route: route.clone(),
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
                .wrapping_add(decode_client_window(&packet, packet.window_scale.unwrap_or(0))),
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
            reported: super::super::state_machine::ReportedFlowMetrics::default(),
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

    pub(super) async fn begin_pending_connect(&self, key: TcpFlowKey) -> bool {
        let mut guard = self.inner.pending_connects.lock().await;
        guard.insert(key)
    }

    pub(super) async fn finish_pending_connect(&self, key: &TcpFlowKey) {
        self.inner.pending_connects.lock().await.remove(key);
    }

    pub(super) async fn insert_flow(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
    ) -> Result<()> {
        if self.inner.flows.read().await.len() >= self.inner.max_flows {
            if let Some(evicted_key) = self.oldest_flow_key().await {
                self.abort_flow_with_rst(&evicted_key, "evicted").await;
            } else {
                bail!("TUN TCP flow table limit reached and no flow could be evicted");
            }
        }

        let (group_name, uplink_name) = {
            let state = flow.lock().await;
            (state.manager.group_name().to_string(), state.uplink_name.clone())
        };
        {
            let mut guard = self.inner.flows.write().await;
            guard.insert(key, flow);
        }
        metrics::record_tun_tcp_event(&group_name, &uplink_name, "flow_created");

        Ok(())
    }

    pub(super) async fn abort_flow_with_rst(&self, key: &TcpFlowKey, reason: &'static str) {
        let flow = self.inner.flows.write().await.remove(key);
        let Some(flow) = flow else {
            return;
        };

        let (flow_id, group_name, uplink_name, _duration, upstream_writer, close_signal, rst_packet) = {
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
                state.manager.group_name().to_string(),
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
        metrics::record_tun_tcp_event(&group_name, &uplink_name, reason);
        debug!(flow_id, uplink = %uplink_name, reason, "aborted TUN TCP flow");
        self.maybe_shrink_flow_table().await;
    }

    pub(super) async fn close_flow(&self, key: &TcpFlowKey, reason: &'static str) {
        let flow = self.inner.flows.write().await.remove(key);
        if let Some(flow) = flow {
            let (flow_id, group_name, uplink_name, _duration, upstream_writer, close_signal) = {
                let mut state = flow.lock().await;
                set_flow_status(&mut state, TcpFlowStatus::Closed);
                clear_flow_metrics(&mut state);
                (
                    state.id,
                    state.manager.group_name().to_string(),
                    state.uplink_name.clone(),
                    state.created_at.elapsed(),
                    state.upstream_writer.clone(),
                    state.close_signal.clone(),
                )
            };
            let _ = close_signal.send(true);
            close_upstream_writer(upstream_writer).await;
            metrics::record_tun_tcp_event(&group_name, &uplink_name, reason);
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
