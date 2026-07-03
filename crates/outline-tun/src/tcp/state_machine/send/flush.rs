use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;

use super::super::super::{
    GSO_MAX_SUPER_SEGMENT_PAYLOAD, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH,
    TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL,
};
use super::super::bbr::{pacing_active, pacing_release_at, refill_pacing_credit};
use super::super::congestion::{congestion_window_remaining, server_max_segment_payload};
use super::super::packets::{build_flow_packet, build_gso_flow_packet, send_window_remaining};
use super::super::transitions::{reset_zero_window_persist, set_flow_status};
use super::super::types::{
    ServerDataPacket, ServerFlush, ServerSegment, TcpFlowState, TcpFlowStatus,
};
use super::buffer::server_window_stalled;

fn flush_server_data(state: &mut TcpFlowState) -> Result<Vec<ServerDataPacket>> {
    // Downlink pacing (BBR): refill the token bucket for elapsed time, then
    // spend it per write. When credit runs out with data still queued we stop
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
        match state.pending_server_data.front() {
            None => break,
            Some(front) if front.is_empty() => {
                state.pending_server_data.pop_front();
                continue;
            },
            Some(_) => {},
        }

        // How much to emit in one write: a single MSS on the plain path, or up
        // to a GSO super-segment when the fd supports TSO. Bounded by the send
        // window and, when pacing, the current credit.
        let per_write_cap = if state.gso_enabled {
            GSO_MAX_SUPER_SEGMENT_PAYLOAD
        } else {
            max_payload_per_segment
        };
        let mut target = per_write_cap.min(available_window as usize);
        if pacing {
            target = target.min(state.bbr.pacing_credit as usize);
        }
        // Pacing gate: no credit for even a byte — arm a wakeup for one MSS.
        if target == 0 {
            state.bbr.pacing_next_at = Some(pacing_release_at(state, max_payload_per_segment));
            break;
        }

        let payload = take_pending_server_payload(state, target);
        if payload.is_empty() {
            break;
        }
        let payload_len = payload.len();
        // App-limited when nothing remains queued after this write: the
        // delivery-rate sample reflects our supply, not the path, so BBR may
        // only let it raise BtlBw, never lower it.
        let app_limited = state.pending_server_data.is_empty();

        let sequence_number = state.server_seq;
        let acknowledgement_number = state.rcv_nxt;
        let flags = TCP_FLAG_ACK | TCP_FLAG_PSH;

        // The wire packet is one super-segment (TSO) or one MSS packet, but the
        // retransmit/SACK/BBR scoreboard always tracks per-MSS segments so a
        // loss inside a super-segment is recovered at MSS granularity.
        let data_packet = if state.gso_enabled && payload_len > max_payload_per_segment {
            let (bytes, vnet) = build_gso_flow_packet(
                state,
                sequence_number,
                acknowledgement_number,
                flags,
                max_payload_per_segment as u16,
                &payload,
            )?;
            ServerDataPacket { bytes, vnet: Some(vnet) }
        } else {
            let bytes =
                build_flow_packet(state, sequence_number, acknowledgement_number, flags, &payload)?;
            ServerDataPacket::single(bytes)
        };
        push_unacked_segments(
            state,
            sequence_number,
            acknowledgement_number,
            flags,
            &payload,
            max_payload_per_segment,
            app_limited,
        );

        state.server_seq = state.server_seq.wrapping_add(payload_len as u32);
        if pacing {
            state.bbr.pacing_credit = state.bbr.pacing_credit.saturating_sub(payload_len as u64);
        }
        reset_zero_window_persist(state);
        packets.push(data_packet);
        available_window =
            send_window_remaining(state).min(congestion_window_remaining(state) as u32);
    }

    Ok(packets)
}

/// Take up to `target` bytes off the pending downlink queue as one buffer. Fast
/// path (the first chunk already covers `target`) is a zero-copy `split_to`;
/// otherwise chunks are coalesced into one allocation for a TSO super-segment.
fn take_pending_server_payload(state: &mut TcpFlowState, target: usize) -> Bytes {
    if let Some(front) = state.pending_server_data.front_mut()
        && front.len() >= target
    {
        let payload = front.split_to(target);
        if front.is_empty() {
            state.pending_server_data.pop_front();
        }
        state.pending_server_bytes_total -= payload.len();
        return payload;
    }
    let mut buffer = Vec::with_capacity(target);
    while buffer.len() < target {
        let Some(front) = state.pending_server_data.front_mut() else {
            break;
        };
        if front.is_empty() {
            state.pending_server_data.pop_front();
            continue;
        }
        let take = front.len().min(target - buffer.len());
        buffer.extend_from_slice(&front[..take]);
        let _ = front.split_to(take);
        if front.is_empty() {
            state.pending_server_data.pop_front();
        }
        state.pending_server_bytes_total -= take;
    }
    Bytes::from(buffer)
}

/// Register the just-sent `payload` on the retransmit scoreboard as per-MSS
/// segments (so a hole inside a TSO super-segment is retransmitted at MSS
/// granularity). `payload` is sliced zero-copy. All segments share the send
/// instant and delivered snapshot — they left the stack in one write.
#[allow(clippy::too_many_arguments)]
fn push_unacked_segments(
    state: &mut TcpFlowState,
    start_sequence: u32,
    acknowledgement_number: u32,
    flags: u8,
    payload: &Bytes,
    mss: usize,
    app_limited: bool,
) {
    let sent_at = Instant::now();
    let delivered_snapshot = state.bbr.delivered;
    let mut offset = 0;
    let mut sequence_number = start_sequence;
    while offset < payload.len() {
        let end = (offset + mss).min(payload.len());
        let segment_len = (end - offset) as u32;
        state.unacked_server_segments.push_back(ServerSegment {
            sequence_number,
            acknowledgement_number,
            flags,
            payload: payload.slice(offset..end),
            last_sent: sent_at,
            first_sent: sent_at,
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot,
            app_limited,
        });
        sequence_number = sequence_number.wrapping_add(segment_len);
        offset = end;
    }
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
