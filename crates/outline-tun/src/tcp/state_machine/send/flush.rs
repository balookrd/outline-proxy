use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;

use super::super::super::{
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL,
};
use super::super::bbr::{pacing_active, pacing_release_at, refill_pacing_credit};
use super::super::congestion::{congestion_window_remaining, server_max_segment_payload};
use super::super::packets::{build_flow_packet, send_window_remaining};
use super::super::transitions::{reset_zero_window_persist, set_flow_status};
use super::super::types::{ServerFlush, ServerSegment, TcpFlowState, TcpFlowStatus};
use super::buffer::server_window_stalled;

fn flush_server_data(state: &mut TcpFlowState) -> Result<Vec<Vec<u8>>> {
    // Downlink pacing (BBR): refill the token bucket for elapsed time, then
    // spend it per segment. When credit runs out with data still queued we stop
    // and arm `pacing_next_at`, so a maintenance wakeup resumes the flush — but
    // on a live flow the next ACK re-enters this flush and refills, so the timer
    // is only a fallback for app-limited/idle gaps. Refilling here, on the
    // ACK-clocked flush, is what keeps timer granularity from capping
    // throughput — the failure mode that sank the reverted fixed-rate pacer.
    let now = Instant::now();
    refill_pacing_credit(state, now);
    let pacing = pacing_active(state);
    state.bbr.pacing_next_at = None;

    let mut packets = Vec::new();
    let mut available_window =
        send_window_remaining(state).min(congestion_window_remaining(state) as u32);
    let max_payload_per_segment = server_max_segment_payload(state);

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
            .min(max_payload_per_segment)
            .min(available_window as usize);

        // Pacing gate: stop once the next segment would exceed available credit,
        // and schedule the wakeup for when enough will have refilled.
        if pacing && (state.bbr.pacing_credit as usize) < payload_len {
            state.bbr.pacing_next_at = Some(pacing_release_at(state, payload_len));
            break;
        }

        let payload = front.split_to(payload_len);
        if front.is_empty() {
            state.pending_server_data.pop_front();
        }
        // App-limited when nothing remains queued after this segment: its
        // delivery-rate sample reflects our supply, not the path, so BBR may
        // only let it raise BtlBw, never lower it.
        let app_limited = state.pending_server_data.is_empty();

        let sequence_number = state.server_seq;
        let acknowledgement_number = state.rcv_nxt;
        let packet = build_flow_packet(
            state,
            sequence_number,
            acknowledgement_number,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            &payload,
        )?;
        state.server_seq = state.server_seq.wrapping_add(payload.len() as u32);
        if pacing {
            state.bbr.pacing_credit = state.bbr.pacing_credit.saturating_sub(payload.len() as u64);
        }
        state.unacked_server_segments.push_back(ServerSegment {
            sequence_number,
            acknowledgement_number,
            flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
            payload,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot: state.bbr.delivered,
            app_limited,
        });
        reset_zero_window_persist(state);
        packets.push(packet);
        available_window =
            send_window_remaining(state).min(congestion_window_remaining(state) as u32);
    }

    Ok(packets)
}

pub(in crate::tcp) fn flush_server_output(state: &mut TcpFlowState) -> Result<ServerFlush> {
    if state.status == TcpFlowStatus::SynReceived {
        return Ok(ServerFlush::default());
    }
    let data_packets = flush_server_data(state)?;
    let window_stalled = server_window_stalled(state);
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
        || matches!(state.status, TcpFlowStatus::Closed | TcpFlowStatus::TimeWait)
    {
        return Ok(None);
    }

    let packet = build_flow_packet(
        state,
        state.server_seq,
        state.rcv_nxt,
        TCP_FLAG_FIN | TCP_FLAG_ACK,
        &[],
    )?;
    let sequence_number = state.server_seq;
    state.server_seq = state.server_seq.wrapping_add(1);
    state.server_fin_pending = false;
    match state.status {
        TcpFlowStatus::CloseWait => set_flow_status(state, TcpFlowStatus::LastAck),
        TcpFlowStatus::SynReceived | TcpFlowStatus::Established => {
            set_flow_status(state, TcpFlowStatus::FinWait1);
        },
        TcpFlowStatus::FinWait1
        | TcpFlowStatus::FinWait2
        | TcpFlowStatus::Closing
        | TcpFlowStatus::LastAck
        | TcpFlowStatus::TimeWait
        | TcpFlowStatus::Closed => {},
    }
    state.unacked_server_segments.push_back(ServerSegment {
        sequence_number,
        acknowledgement_number: state.rcv_nxt,
        flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
        payload: Bytes::new(),
        last_sent: Instant::now(),
        first_sent: Instant::now(),
        retransmits: 0,
        rto_retransmits: 0,
        fast_retransmit_epoch: 0,
        delivered_snapshot: state.bbr.delivered,
        app_limited: true,
    });
    Ok(Some(packet))
}

pub(in crate::tcp) fn maybe_emit_zero_window_probe(
    state: &mut TcpFlowState,
) -> Result<Option<Vec<u8>>> {
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
        state.rcv_nxt,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        &[probe_byte],
    )?;
    let current = state.zero_window_probe_backoff;
    state.next_zero_window_probe_at = Some(now + current);
    state.zero_window_probe_backoff =
        (current.saturating_mul(2)).min(TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL);
    Ok(Some(packet))
}
