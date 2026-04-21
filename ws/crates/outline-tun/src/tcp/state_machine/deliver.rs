use anyhow::Result;

use super::super::TCP_FLAG_ACK;
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
        state.client_next_seq,
    );
    let segment = normalize_trimmed_segment(trimmed, state.client_next_seq);
    let mut pending_payload = Vec::with_capacity(trimmed.payload.len());
    let mut should_close_client_half = false;

    if !segment.payload.is_empty() || segment.fin {
        apply_client_segment(
            &mut state.client_next_seq,
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
    let client_next_seq = state.client_next_seq;
    let server_flush = flush_server_output(state)?;

    let pending_ack = if should_send_ack {
        Some(build_flow_ack_packet(state, server_seq, client_next_seq, TCP_FLAG_ACK)?)
    } else {
        None
    };

    Ok(DeliverOutcome {
        pending_payload,
        should_close_client_half,
        server_flush,
        pending_ack,
    })
}
