use std::time::Instant;

use anyhow::Result;

use super::super::{TCP_DELAYED_ACK_TIMEOUT, TCP_FLAG_ACK};
use super::packets::build_flow_ack_packet;
use super::policy::segment_requires_ack;
use super::recv::{
    TrimmedSegment, apply_client_segment, drain_ready_buffered_segments_from_state,
    normalize_trimmed_segment,
};
use super::send::flush_server_output;
use super::types::{ServerFlush, TcpFlowState};

// Bundled output of processing one in-window inbound segment: what to
// hand to the upstream writer, what to send back down the TUN, and
// whether the client's half has closed. The engine is responsible for
// the actual IO and the post-close transition.
pub(in crate::tcp) struct DeliverOutcome {
    pub(in crate::tcp) pending_payload: Vec<u8>,
    pub(in crate::tcp) should_close_client_half: bool,
    pub(in crate::tcp) server_flush: ServerFlush,
    pub(in crate::tcp) pending_ack: Option<Vec<u8>>,
}

pub(in crate::tcp) fn apply_inbound_and_flush(
    state: &mut TcpFlowState,
    trimmed: &TrimmedSegment,
) -> Result<DeliverOutcome> {
    // Decide the ACK policy against the pre-apply expected sequence.
    let should_send_ack = segment_requires_ack(
        trimmed.sequence_number,
        trimmed.flags,
        trimmed.payload.len(),
        state.rcv_nxt,
    );
    // Snapshot before apply: buffered out-of-order segments mean we are in a
    // SACK hole (or about to fill one), which must ACK immediately so the peer's
    // fast-retransmit / SACK path sees progress without waiting for the timer.
    let had_buffered_segments = !state.pending_client_segments.is_empty();
    let carries_data = !trimmed.payload.is_empty();
    let segment = normalize_trimmed_segment(trimmed, state.rcv_nxt);
    let mut pending_payload = Vec::with_capacity(trimmed.payload.len());
    let mut should_close_client_half = false;

    if !segment.payload.is_empty() || segment.fin {
        apply_client_segment(
            &mut state.rcv_nxt,
            segment,
            &mut pending_payload,
            &mut should_close_client_half,
        );
        if !should_close_client_half {
            should_close_client_half =
                drain_ready_buffered_segments_from_state(state, &mut pending_payload);
        }
    }

    let server_seq = state.server_seq;
    let rcv_nxt = state.rcv_nxt;
    let server_flush = flush_server_output(state)?;

    let pending_ack = resolve_client_ack(
        state,
        should_send_ack,
        carries_data,
        should_close_client_half,
        had_buffered_segments,
        &server_flush,
        server_seq,
        rcv_nxt,
    )?;

    Ok(DeliverOutcome {
        pending_payload,
        should_close_client_half,
        server_flush,
        pending_ack,
    })
}

/// Clear any owed delayed ACK. Called wherever an ACK covering the current
/// `rcv_nxt` is emitted (immediate ACK, timer-fired ACK, or a piggybacked
/// downlink data packet) so the maintenance loop does not later send a
/// redundant standalone ACK.
pub(in crate::tcp) fn clear_delayed_ack(state: &mut TcpFlowState) {
    state.unacked_in_order_segments = 0;
    state.delayed_ack_deadline = None;
}

/// Resolve whether this inbound segment produces an immediate standalone ACK,
/// defers one (arming the delayed-ACK timer), or none. Returns the built ACK
/// packet only for the immediate case; deferred/none return `None`.
#[allow(clippy::too_many_arguments)]
fn resolve_client_ack(
    state: &mut TcpFlowState,
    should_send_ack: bool,
    carries_data: bool,
    is_fin: bool,
    had_buffered_segments: bool,
    server_flush: &ServerFlush,
    server_seq: u32,
    rcv_nxt: u32,
) -> Result<Option<Vec<u8>>> {
    if !should_send_ack {
        return Ok(None);
    }

    // A downlink data packet in this same flush already carries our `rcv_nxt`
    // as its ACK number, so the client is acked without a standalone packet.
    if !server_flush.data_packets.is_empty() {
        clear_delayed_ack(state);
        return Ok(None);
    }

    // Emit immediately (never defer) when the peer needs the ACK promptly:
    // a FIN; a pure control/duplicate segment (no data, so this is a FIN or an
    // old-sequence retransmit); any segment touching a reassembly hole (SACK
    // precision and hole-fill); or the 2nd in-order segment since the last ACK
    // (RFC 5681 "ack every other segment").
    let immediate = is_fin
        || !carries_data
        || had_buffered_segments
        || !state.pending_client_segments.is_empty()
        || state.unacked_in_order_segments >= 1;
    if immediate {
        clear_delayed_ack(state);
        return Ok(Some(build_flow_ack_packet(state, server_seq, rcv_nxt, TCP_FLAG_ACK)?));
    }

    // Lone in-order full-sized segment: defer the ACK and arm the timer so the
    // maintenance loop flushes it if a 2nd segment does not arrive first.
    state.unacked_in_order_segments = state.unacked_in_order_segments.saturating_add(1);
    if state.delayed_ack_deadline.is_none() {
        state.delayed_ack_deadline = Some(Instant::now() + TCP_DELAYED_ACK_TIMEOUT);
    }
    Ok(None)
}
