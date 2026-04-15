use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::sync::Mutex;

use crate::metrics;
use crate::uplink::TransportKind;

use super::super::maintenance::sync_flow_metrics_and_wake;
use super::super::state_machine::{
    TcpFlowState, TcpFlowStatus, apply_client_segment, build_flow_ack_packet, build_flow_packet,
    build_flow_syn_ack_packet, client_fin_seen, drain_ready_buffered_segments_from_state,
    exceeds_client_reassembly_limits, flush_server_output, is_duplicate_syn,
    normalize_client_segment, note_ack_progress, note_recent_client_timestamp, process_server_ack,
    queue_future_segment_with_recv_window, reset_zero_window_persist, retransmit_budget_exhausted,
    retransmit_oldest_unacked_packet, seq_gt, seq_lt, server_fin_awaiting_ack, set_flow_status,
    transition_on_client_fin, transition_on_server_fin_ack, trim_packet_to_receive_window,
    update_client_send_window,
};
use super::super::validation::{PacketValidation, validate_existing_packet};
use super::super::wire::ParsedTcpPacket;
use super::super::{TCP_FLAG_ACK, TCP_FLAG_FIN};
use super::{TunTcpEngine, close_upstream_writer, ip_family_from_version, key_uplink_name};

impl TunTcpEngine {
    pub(super) async fn handle_existing_flow(
        &self,
        flow: Arc<Mutex<TcpFlowState>>,
        packet: ParsedTcpPacket,
    ) -> Result<()> {
        let manager = { flow.lock().await.manager.clone() };
        if manager.strict_active_uplink_for(TransportKind::Tcp) {
            let active_uplink =
                manager.active_uplink_index_for_transport(TransportKind::Tcp).await;
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
            PacketValidation::Accept => {},
            PacketValidation::Ignore => return Ok(()),
            PacketValidation::CloseFlow(reason) => {
                let key = state.key.clone();
                drop(state);
                self.close_flow(&key, reason).await;
                if reason == "client_rst" {
                    metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_rst_observed");
                }
                return Ok(());
            },
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
            },
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

        let ack_effect =
            process_server_ack(&mut state, packet.acknowledgement_number, &packet.sack_blocks);
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
                    self.abort_flow_with_rst(&key, "retransmit_budget_exhausted").await;
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
                self.abort_flow_with_rst(&key, "client_reassembly_limit").await;
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
        let flow_manager = state.manager.clone();
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
                        &flow_manager,
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
}
