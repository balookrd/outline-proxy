use std::time::{Duration, Instant};

use anyhow::Result;

use super::super::super::TCP_FLAG_ACK;
use super::super::congestion::{
    current_retransmission_timeout, fast_retransmit_index, preferred_retransmit_index,
    rebuild_unacked_accounting, server_segment_is_sacked,
};
use super::super::packets::{build_flow_ack_packet, build_flow_data_header};
use super::super::types::{ServerDataPacket, TcpFlowState, TcpFlowStatus};

/// True when the flow is quiet enough that a keepalive probe is safe
/// and useful: fully established, no data to send or in-flight.
pub(in crate::tcp) fn keepalive_probe_eligible(state: &TcpFlowState) -> bool {
    state.status == TcpFlowStatus::Established
        && state.pending_server_data.is_empty()
        && state.unacked_server_segments.is_empty()
}

/// Scheduled time for the next keepalive probe, or `None` when
/// keepalives are disabled or the flow is not eligible.
pub(in crate::tcp) fn next_keepalive_deadline(
    state: &TcpFlowState,
    keepalive_idle: Option<Duration>,
    keepalive_interval: Duration,
) -> Option<Instant> {
    let idle = keepalive_idle?;
    if !keepalive_probe_eligible(state) {
        return None;
    }
    Some(match state.last_keepalive_probe_at {
        Some(last) => last + keepalive_interval,
        None => state.timestamps.last_seen + idle,
    })
}

/// Emit a keepalive probe (ACK carrying seq = SND.NXT−1) when the flow
/// has been idle for `keepalive_idle` or since the previous probe by
/// `keepalive_interval`. The probe byte is one below the already-acked
/// send sequence, so the peer replies with a pure ACK; this traverses
/// any stateful middlebox in both directions and refreshes NAT bindings.
pub(in crate::tcp) fn maybe_emit_keepalive_probe(
    state: &mut TcpFlowState,
    keepalive_idle: Option<Duration>,
    keepalive_interval: Duration,
) -> Result<Option<Vec<u8>>> {
    let Some(deadline) = next_keepalive_deadline(state, keepalive_idle, keepalive_interval) else {
        return Ok(None);
    };
    let now = Instant::now();
    if deadline > now {
        return Ok(None);
    }
    let probe_seq = state.server_seq.wrapping_sub(1);
    let packet = build_flow_ack_packet(state, probe_seq, state.rcv_nxt, TCP_FLAG_ACK)?;
    state.keepalive_probes_sent = state.keepalive_probes_sent.saturating_add(1);
    state.last_keepalive_probe_at = Some(now);
    Ok(Some(packet))
}

pub(in crate::tcp) fn retransmit_oldest_unacked_packet(
    state: &mut TcpFlowState,
) -> Result<Option<ServerDataPacket>> {
    let index = fast_retransmit_index(state);
    let Some(index) = index else {
        return Ok(None);
    };
    let epoch = state.recovery_epoch;
    let (sequence_number, acknowledgement_number, flags, payload) = {
        let segment = &mut state.unacked_server_segments[index];
        segment.last_sent = Instant::now();
        // Karn: count every wire put-back so RTT samples skip retransmits.
        segment.retransmits = segment.retransmits.saturating_add(1);
        // Mark this hole as resent in the current episode so a follow-up
        // partial SACK does not re-fire it; the RTO path covers a lost resend.
        segment.fast_retransmit_epoch = epoch;
        (
            segment.sequence_number,
            segment.acknowledgement_number,
            segment.flags,
            // Zero-copy: the scoreboard's owned `Bytes` is written vectored, not
            // copied into the packet.
            segment.payload.clone(),
        )
    };
    // Rewriting `last_sent` can reorder send instants; refresh the earliest /
    // reordered accounting (pipe membership is unchanged — still un-SACKed).
    rebuild_unacked_accounting(state);
    // A retransmit is always a single MSS segment, never a TSO super-segment.
    let header = build_flow_data_header(
        state,
        sequence_number,
        state.rcv_nxt.max(acknowledgement_number),
        flags,
        &[payload.as_ref()],
    )?;
    Ok(Some(ServerDataPacket {
        header,
        payload: vec![payload],
        vnet: None,
    }))
}

pub(in crate::tcp) fn retransmit_due_segment(
    state: &mut TcpFlowState,
) -> Result<Option<ServerDataPacket>> {
    let Some(index) = preferred_retransmit_index(state)
        .filter(|index| {
            state.unacked_server_segments[*index].last_sent.elapsed()
                >= current_retransmission_timeout(state)
        })
        .or_else(|| {
            let rto = current_retransmission_timeout(state);
            state.unacked_server_segments.iter().position(|segment| {
                !server_segment_is_sacked(state, segment) && segment.last_sent.elapsed() >= rto
            })
        })
    else {
        return Ok(None);
    };
    let (sequence_number, acknowledgement_number, flags, payload) = {
        let segment = &mut state.unacked_server_segments[index];
        segment.last_sent = Instant::now();
        segment.retransmits = segment.retransmits.saturating_add(1);
        // RTO-driven resend: this is the genuine dead-path signal the budget
        // abort keys off (see `retransmit_budget_exhausted`).
        segment.rto_retransmits = segment.rto_retransmits.saturating_add(1);
        (
            segment.sequence_number,
            segment.acknowledgement_number,
            segment.flags,
            segment.payload.clone(),
        )
    };
    // Rewriting `last_sent` can reorder send instants; refresh the earliest /
    // reordered accounting (pipe membership is unchanged — still un-SACKed).
    rebuild_unacked_accounting(state);
    let header = build_flow_data_header(
        state,
        sequence_number,
        state.rcv_nxt.max(acknowledgement_number),
        flags,
        &[payload.as_ref()],
    )?;
    Ok(Some(ServerDataPacket {
        header,
        payload: vec![payload],
        vnet: None,
    }))
}
