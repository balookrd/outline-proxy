use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;

use outline_metrics as metrics;

use super::super::maintenance::commit_flow_changes;
use super::super::state_machine::{
    InboundSegmentDisposition, QueueFutureSegmentOutcome, TcpFlowState, TcpFlowStatus,
    absorb_accepted_client_packet, ack_covers_server_fin, ack_is_stale_server_fin_retry,
    apply_inbound_and_flush, build_flow_ack_packet, build_flow_packet, classify_inbound_segment,
    client_fin_seen, completes_syn_received_handshake, exceeds_client_reassembly_limits,
    is_duplicate_syn, note_ack_progress, process_server_ack,
    queue_future_segment_with_recv_window, retransmit_budget_exhausted,
    retransmit_oldest_unacked_packet, segment_requires_ack, server_fin_awaiting_ack,
    set_flow_status, transition_on_client_fin, transition_on_server_fin_ack,
};
use super::super::validation::{PacketValidation, validate_existing_packet};
use super::super::wire::ParsedTcpPacket;
use super::super::{TCP_FLAG_ACK, TCP_FLAG_FIN};
use super::{TunTcpEngine, close_upstream_writer, ip_family_from_version, should_migrate_tcp_flow};

impl TunTcpEngine {
    pub(super) async fn handle_existing_flow(
        &self,
        flow: Arc<Mutex<TcpFlowState>>,
        packet: ParsedTcpPacket,
    ) -> Result<()> {
        let (uplink_index, manager, flow_key) = {
            let state = flow.lock().await;
            (state.routing.uplink_index, state.routing.manager.clone(), state.key.clone())
        };
        if should_migrate_tcp_flow(&manager, uplink_index).await {
            self.abort_flow_with_rst(&flow_key, "global_switch").await;
            return Ok(());
        }

        let ip_family = ip_family_from_version(packet.version);
        let mut state = flow.lock().await;

        if state.status == TcpFlowStatus::SynReceived
            && is_duplicate_syn(&packet, state.client_next_seq)
        {
            metrics::record_tun_tcp_event(
                &state.routing.group_name,
                &state.routing.uplink_name,
                "duplicate_syn",
            );
            return self.write_syn_ack_and_drop(state, ip_family).await;
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
                let group_name = state.routing.group_name.clone();
                let uplink_name = state.routing.uplink_name.clone();
                let ack = build_flow_ack_packet(
                    &state,
                    state.server_seq,
                    state.client_next_seq,
                    TCP_FLAG_ACK,
                )?;
                drop(state);
                self.write_ack_packet_with_event(
                    &key,
                    ack,
                    ip_family,
                    &group_name,
                    &uplink_name,
                    event,
                )
                .await?;
                return Ok(());
            },
        }

        absorb_accepted_client_packet(&mut state, &packet);
        commit_flow_changes(&mut state, &self.inner.tcp);

        if state.status == TcpFlowStatus::SynReceived {
            if completes_syn_received_handshake(
                packet.flags,
                packet.acknowledgement_number,
                packet.sequence_number,
                state.server_seq,
                state.client_next_seq,
            ) {
                set_flow_status(&mut state, TcpFlowStatus::Established);
                commit_flow_changes(&mut state, &self.inner.tcp);
            } else {
                return self.write_syn_ack_and_drop(state, ip_family).await;
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
            commit_flow_changes(&mut state, &self.inner.tcp);
        }

        if server_fin_awaiting_ack(state.status)
            && ack_covers_server_fin(packet.flags, packet.acknowledgement_number, state.server_seq)
        {
            if transition_on_server_fin_ack(&mut state) {
                let key = state.key.clone();
                drop(state);
                self.close_flow(&key, "last_ack_acked").await;
                return Ok(());
            }
            commit_flow_changes(&mut state, &self.inner.tcp);
        }

        if ack_effect.retransmit_now {
            metrics::record_tun_tcp_event(
                &state.routing.group_name,
                &state.routing.uplink_name,
                "fast_retransmit",
            );
            if let Some(packet) = retransmit_oldest_unacked_packet(&mut state)? {
                if retransmit_budget_exhausted(&state, &self.inner.tcp) {
                    let key = state.key.clone();
                    drop(state);
                    self.abort_flow_with_rst(&key, "retransmit_budget_exhausted").await;
                    return Ok(());
                }
                commit_flow_changes(&mut state, &self.inner.tcp);
                let key = state.key.clone();
                drop(state);
                self.write_tun_packet_or_close_flow(&key, &packet).await?;
                metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_retransmit");
                return Ok(());
            }
        }

        if server_fin_awaiting_ack(state.status)
            && ack_is_stale_server_fin_retry(
                packet.flags,
                packet.acknowledgement_number,
                state.server_seq,
            )
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
            && segment_requires_ack(
                packet.sequence_number,
                packet.flags,
                packet.payload.len(),
                state.client_next_seq,
            )
        {
            return self.write_pure_ack_and_drop(state, ip_family).await;
        }

        let trimmed = match classify_inbound_segment(&state, &packet) {
            InboundSegmentDisposition::BeyondExpectedSequence => {
                match queue_future_segment_with_recv_window(&mut state, &self.inner.tcp, &packet) {
                    QueueFutureSegmentOutcome::WouldExceedLimits => {
                        let key = state.key.clone();
                        drop(state);
                        self.abort_flow_with_rst(&key, "client_reassembly_limit").await;
                        return Ok(());
                    },
                    QueueFutureSegmentOutcome::OutsideWindow
                    | QueueFutureSegmentOutcome::Queued => {},
                }
                commit_flow_changes(&mut state, &self.inner.tcp);
                return self.write_pure_ack_and_drop(state, ip_family).await;
            },
            InboundSegmentDisposition::OutsideReceiveWindow => {
                return self.write_pure_ack_and_drop(state, ip_family).await;
            },
            InboundSegmentDisposition::Deliver(trimmed) => trimmed,
        };

        let mut outcome = apply_inbound_and_flush(&mut state, &trimmed)?;
        commit_flow_changes(&mut state, &self.inner.tcp);

        let key = state.key.clone();
        let uplink_index = state.routing.uplink_index;
        let uplink_name = state.routing.uplink_name.clone();
        let group_name = state.routing.group_name.clone();
        let flow_manager = state.routing.manager.clone();
        let upstream_writer = state.routing.upstream_writer.clone();

        // If there is no upstream writer yet (connect still in flight),
        // queue the payload onto `pending_client_data` under the same
        // lock we already hold rather than dropping and re-acquiring.
        // `buffered_client_bytes` sums both pending_client_data and
        // pending_client_segments, so this uses the same cap as the
        // out-of-order reassembly path.
        let abort_for_pending_limit =
            if !outcome.pending_payload.is_empty() && upstream_writer.is_none() {
                state
                    .pending_client_data
                    .push_back(std::mem::take(&mut outcome.pending_payload).into());
                let over_limit = exceeds_client_reassembly_limits(&state, &self.inner.tcp);
                if !over_limit {
                    commit_flow_changes(&mut state, &self.inner.tcp);
                }
                over_limit
            } else {
                false
            };

        // Apply the client-FIN transition before releasing the lock so we
        // don't re-acquire it just to mutate state after the async writes
        // below. The actual upstream-writer close is async and stays past
        // the drop point.
        if outcome.should_close_client_half {
            transition_on_client_fin(&mut state);
            commit_flow_changes(&mut state, &self.inner.tcp);
        }

        drop(state);

        if abort_for_pending_limit {
            self.abort_flow_with_rst(&key, "client_pending_data_limit").await;
            return Ok(());
        }

        if !outcome.pending_payload.is_empty() {
            if let Some(upstream_writer) = upstream_writer.clone() {
                let send_result = {
                    let mut upstream_writer = upstream_writer.lock().await;
                    upstream_writer.send_chunk(&outcome.pending_payload).await
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
                    flow_manager.group_name(),
                    &uplink_name,
                    outcome.pending_payload.len(),
                );
            }
        }

        if let Some(ack) = outcome.pending_ack {
            self.write_tun_packet_or_close_flow(&key, &ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
        }

        self.write_server_flush_or_close(&key, outcome.server_flush, &group_name, &uplink_name)
            .await?;

        if outcome.should_close_client_half {
            close_upstream_writer(upstream_writer).await;
        }

        Ok(())
    }
}
