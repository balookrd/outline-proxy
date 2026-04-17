use std::collections::VecDeque;

use bytes::Bytes;

use crate::config::TunTcpConfig;

use super::super::{ParsedTcpPacket, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_SYN};
use super::packets::{buffered_client_bytes, receive_window_end};
use super::seq::{seq_ge, seq_gt, seq_lt};
use super::types::{BufferedClientSegment, ClientSegmentView, TcpFlowState};

pub(in crate::tun_tcp) fn trim_packet_to_receive_window(
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

pub(in crate::tun_tcp) fn normalize_client_segment(
    packet: &ParsedTcpPacket,
    expected_seq: u32,
) -> ClientSegmentView {
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
        Bytes::new()
    } else {
        Bytes::copy_from_slice(&payload[overlap..])
    };

    let fin = if (flags & TCP_FLAG_FIN) == 0 {
        false
    } else {
        overlap <= original_payload_len
    };

    ClientSegmentView { payload, fin }
}

fn buffered_client_segment_data_end(segment: &BufferedClientSegment) -> u32 {
    segment.sequence_number.wrapping_add(segment.payload.len() as u32)
}

fn client_segment_has_fin(segment: &BufferedClientSegment) -> bool {
    (segment.flags & TCP_FLAG_FIN) != 0
}

fn insert_client_segment(
    pending_segments: &mut VecDeque<BufferedClientSegment>,
    segment: BufferedClientSegment,
    expected_seq: u32,
) {
    let insert_index = pending_segments
        .iter()
        .position(|existing| {
            existing.sequence_number.wrapping_sub(expected_seq)
                > segment.sequence_number.wrapping_sub(expected_seq)
        })
        .unwrap_or(pending_segments.len());
    pending_segments.insert(insert_index, segment);
}

pub(in crate::tun_tcp) fn queue_future_segment(
    pending_segments: &mut VecDeque<BufferedClientSegment>,
    packet: &ParsedTcpPacket,
    expected_seq: u32,
) {
    if packet.payload.is_empty() && (packet.flags & TCP_FLAG_FIN) == 0 {
        return;
    }

    let payload_start = packet.sequence_number;
    let payload_end = payload_start.wrapping_add(packet.payload.len() as u32);
    let mut cursor = payload_start;
    let existing_segments = pending_segments.iter().cloned().collect::<Vec<_>>();
    for existing in existing_segments {
        let existing_start = existing.sequence_number;
        let existing_end = buffered_client_segment_data_end(&existing);
        if !seq_gt(existing_end, cursor) {
            continue;
        }
        if !seq_gt(payload_end, existing_start) {
            break;
        }
        if seq_gt(existing_start, cursor) {
            let end = if seq_lt(payload_end, existing_start) {
                payload_end
            } else {
                existing_start
            };
            let start_offset = cursor.wrapping_sub(payload_start) as usize;
            let end_offset = end.wrapping_sub(payload_start) as usize;
            insert_client_segment(
                pending_segments,
                BufferedClientSegment {
                    sequence_number: cursor,
                    flags: packet.flags & TCP_FLAG_ACK,
                    payload: Bytes::copy_from_slice(&packet.payload[start_offset..end_offset]),
                },
                expected_seq,
            );
        }
        if seq_gt(existing_end, cursor) {
            cursor = existing_end;
        }
        if !seq_gt(payload_end, cursor) {
            break;
        }
    }
    if seq_gt(payload_end, cursor) {
        let start_offset = cursor.wrapping_sub(payload_start) as usize;
        insert_client_segment(
            pending_segments,
            BufferedClientSegment {
                sequence_number: cursor,
                flags: packet.flags & TCP_FLAG_ACK,
                payload: Bytes::copy_from_slice(&packet.payload[start_offset..]),
            },
            expected_seq,
        );
    }

    if (packet.flags & TCP_FLAG_FIN) != 0 {
        let fin_sequence = payload_end;
        if !pending_segments.iter().any(|existing| {
            client_segment_has_fin(existing)
                && buffered_client_segment_data_end(existing) == fin_sequence
        }) {
            insert_client_segment(
                pending_segments,
                BufferedClientSegment {
                    sequence_number: fin_sequence,
                    flags: packet.flags & (TCP_FLAG_FIN | TCP_FLAG_ACK),
                    payload: Bytes::new(),
                },
                expected_seq,
            );
        }
    }
}

/// Outcome of a pre-checked reassembly-queue insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tun_tcp) enum QueueFutureSegmentOutcome {
    /// Packet was discarded because it lies entirely outside the receive
    /// window (not a limit violation — normal handling).
    OutsideWindow,
    /// Packet was accepted and queued for reassembly.
    Queued,
    /// Packet would push the flow past its reassembly limits; nothing was
    /// inserted and the caller should abort the flow.
    WouldExceedLimits,
}

pub(in crate::tun_tcp) fn queue_future_segment_with_recv_window(
    state: &mut TcpFlowState,
    config: &TunTcpConfig,
    packet: &ParsedTcpPacket,
) -> QueueFutureSegmentOutcome {
    let Some(trimmed) = trim_packet_to_receive_window(state, packet) else {
        return QueueFutureSegmentOutcome::OutsideWindow;
    };

    // Pre-check: reject BEFORE mutating the reassembly queue. `queue_future_segment`
    // may split the packet into multiple sub-segments (up to 1 payload chunk
    // plus an optional FIN marker), so the upper bound on what gets added is
    // `trimmed.payload.len()` bytes and 2 segments. Checking the pessimistic
    // bound up front means an attacker cannot push the flow past the cap even
    // transiently by sending a single oversized segment.
    let has_fin = (trimmed.flags & TCP_FLAG_FIN) != 0;
    let additional_segments = if trimmed.payload.is_empty() && !has_fin {
        0
    } else if has_fin {
        2
    } else {
        1
    };
    let additional_bytes = trimmed.payload.len();
    if state.pending_client_segments.len() + additional_segments
        > config.max_buffered_client_segments
        || buffered_client_bytes(state) + additional_bytes > config.max_buffered_client_bytes
    {
        return QueueFutureSegmentOutcome::WouldExceedLimits;
    }

    queue_future_segment(&mut state.pending_client_segments, &trimmed, state.client_next_seq);
    QueueFutureSegmentOutcome::Queued
}

pub(in crate::tun_tcp) fn exceeds_client_reassembly_limits(
    state: &TcpFlowState,
    config: &TunTcpConfig,
) -> bool {
    state.pending_client_segments.len() > config.max_buffered_client_segments
        || buffered_client_bytes(state) > config.max_buffered_client_bytes
}

pub(in crate::tun_tcp) fn drain_ready_buffered_segments(
    expected_seq: &mut u32,
    pending_segments: &mut VecDeque<BufferedClientSegment>,
    pending_payload: &mut Vec<u8>,
) -> bool {
    loop {
        let Some(segment) = pending_segments.front() else {
            return false;
        };
        if seq_gt(segment.sequence_number, *expected_seq) {
            return false;
        }
        let segment = pending_segments.pop_front().expect("front exists while draining");
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

pub(in crate::tun_tcp) fn drain_ready_buffered_segments_from_state(
    state: &mut TcpFlowState,
    pending_payload: &mut Vec<u8>,
) -> bool {
    drain_ready_buffered_segments(
        &mut state.client_next_seq,
        &mut state.pending_client_segments,
        pending_payload,
    )
}

pub(in crate::tun_tcp) fn apply_client_segment(
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

pub(in crate::tun_tcp) fn is_duplicate_syn(packet: &ParsedTcpPacket, expected_seq: u32) -> bool {
    (packet.flags & TCP_FLAG_SYN) != 0
        && (packet.flags & TCP_FLAG_ACK) == 0
        && packet.payload.is_empty()
        && packet.sequence_number == expected_seq.wrapping_sub(1)
}
