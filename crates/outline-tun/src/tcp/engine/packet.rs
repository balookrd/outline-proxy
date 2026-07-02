use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;

use outline_metrics as metrics;

use super::super::maintenance::reschedule_flow;
use super::super::state_machine::{
    InboundSegmentDisposition, QueueFutureSegmentOutcome, TcpFlowState, TcpFlowStatus,
    absorb_accepted_client_packet, ack_covers_server_fin, ack_is_stale_server_fin_retry,
    apply_inbound_and_flush, build_flow_ack_packet, build_flow_packet, classify_inbound_segment,
    client_fin_seen, completes_syn_received_handshake, exceeds_client_reassembly_limits,
    is_duplicate_syn, note_ack_progress, process_server_ack, queue_future_segment_with_recv_window,
    retransmit_budget_exhausted, retransmit_oldest_unacked_packet, segment_requires_ack,
    server_fin_awaiting_ack, set_flow_status, sync_flow_metrics, transition_on_client_fin,
    transition_on_server_fin_ack,
};
use super::super::validation::{PacketValidation, validate_existing_packet};
use super::super::wire::ParsedTcpPacket;
use super::super::{TCP_FLAG_ACK, TCP_FLAG_FIN};
use super::{TunTcpEngine, ip_family_from_version, should_migrate_tcp_flow};

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

        if state.status == TcpFlowStatus::SynReceived && is_duplicate_syn(&packet, state.rcv_nxt) {
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
                let ack =
                    build_flow_ack_packet(&state, state.server_seq, state.rcv_nxt, TCP_FLAG_ACK)?;
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
        self.record_flow_activity(&state);
        reschedule_flow(&mut state, &self.inner.tcp);

        if state.status == TcpFlowStatus::SynReceived {
            if completes_syn_received_handshake(
                packet.flags,
                packet.acknowledgement_number,
                packet.sequence_number,
                state.server_seq,
                state.rcv_nxt,
            ) {
                set_flow_status(&mut state, TcpFlowStatus::Established);
                reschedule_flow(&mut state, &self.inner.tcp);
            } else {
                sync_flow_metrics(&mut state);
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
                ack_effect.rate_sample,
            );
            reschedule_flow(&mut state, &self.inner.tcp);
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
            reschedule_flow(&mut state, &self.inner.tcp);
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
                sync_flow_metrics(&mut state);
                reschedule_flow(&mut state, &self.inner.tcp);
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
                state.rcv_nxt,
                TCP_FLAG_FIN | TCP_FLAG_ACK,
                &[],
            )?;
            sync_flow_metrics(&mut state);
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
                state.rcv_nxt,
            )
        {
            sync_flow_metrics(&mut state);
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
                reschedule_flow(&mut state, &self.inner.tcp);
                sync_flow_metrics(&mut state);
                return self.write_pure_ack_and_drop(state, ip_family).await;
            },
            InboundSegmentDisposition::OutsideReceiveWindow => {
                sync_flow_metrics(&mut state);
                return self.write_pure_ack_and_drop(state, ip_family).await;
            },
            InboundSegmentDisposition::Deliver(trimmed) => trimmed,
        };

        let mut outcome = apply_inbound_and_flush(&mut state, &trimmed)?;
        reschedule_flow(&mut state, &self.inner.tcp);

        let key = state.key.clone();
        let uplink_name = state.routing.uplink_name.clone();
        let group_name = state.routing.group_name.clone();

        // Always queue client payload onto `pending_client_data` under the
        // lock we already hold; the per-flow upstream pump drains it. This
        // is the decoupling point — the read-loop never writes upstream
        // inline, so it cannot block on this flow's upstream back-pressure.
        // `buffered_client_bytes` sums pending_client_data and
        // pending_client_segments, so this shares the reassembly cap and,
        // through the advertised receive window, back-pressures the client.
        let mut buffered_client_data = false;
        let abort_for_pending_limit = if !outcome.pending_payload.is_empty() {
            state
                .pending_client_data
                .push_back(std::mem::take(&mut outcome.pending_payload).into());
            buffered_client_data = true;
            let over_limit = exceeds_client_reassembly_limits(&state, &self.inner.tcp);
            if !over_limit {
                reschedule_flow(&mut state, &self.inner.tcp);
            }
            over_limit
        } else {
            false
        };

        // Apply the client-FIN transition before releasing the lock. The
        // upstream-writer half-close now happens in the pump task, after it
        // drains any still-buffered client data, so a FIN can never race
        // ahead of payload that has not yet been sent upstream.
        if outcome.should_close_client_half {
            transition_on_client_fin(&mut state);
            reschedule_flow(&mut state, &self.inner.tcp);
        }

        let pump_notify = state.signals.upstream_pump.clone();
        let server_drain = state.signals.server_drain.clone();
        // Collapse the per-mutation metric syncs into one before releasing the
        // lock: no `.await` runs between the mutations above and here, so a
        // scraper can only ever observe the gauges at this release point. The
        // `abort_for_pending_limit` path skips it — `abort_flow_with_rst` runs
        // `clear_flow_metrics`, which reconciles from the last reported values.
        if !abort_for_pending_limit {
            sync_flow_metrics(&mut state);
        }
        drop(state);

        if abort_for_pending_limit {
            self.abort_flow_with_rst(&key, "client_pending_data_limit").await;
            return Ok(());
        }

        // Hand off to the per-flow upstream pump instead of writing inline:
        // the buffering above plus this wake keep the shared read-loop from
        // ever blocking on upstream back-pressure. Before the writer exists
        // the pump is not spawned yet; connect drains the buffer on start.
        //
        // We wake on the same `upstream_pump` Notify even when the writer is
        // not ready yet: while a flow is in the pre-connect sniffing phase the
        // connect task parks on this Notify waiting for the first client
        // chunk (TLS ClientHello / HTTP request) to peek. A permit issued
        // before the writer exists is harmless to the pump, which drains the
        // buffer unconditionally on start.
        if buffered_client_data || outcome.should_close_client_half {
            pump_notify.notify_one();
        }

        if let Some(ack) = outcome.pending_ack {
            self.write_tun_packet_or_close_flow(&key, &ack).await?;
            metrics::record_tun_packet("upstream_to_tun", ip_family, "tcp_ack");
        }

        // This packet ACKed downlink data, so `flush_server_output` just shipped
        // queued bytes out of `pending_server_data`. Wake the reader in case it
        // is parked on downlink backpressure waiting for the client to make room.
        let drained_downlink = !outcome.server_flush.data_packets.is_empty();
        self.write_server_flush_or_close(&key, outcome.server_flush, &group_name, &uplink_name)
            .await?;
        if drained_downlink {
            server_drain.notify_one();
        }

        Ok(())
    }
}
