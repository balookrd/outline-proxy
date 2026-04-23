use anyhow::Result;
use bytes::Bytes;

use super::super::{
    MAX_SERVER_SEGMENT_PAYLOAD, ParsedTcpPacket, TCP_FLAG_ACK, TCP_FLAG_SYN,
    TCP_SERVER_WINDOW_SCALE, build_response_packet_custom,
};
use super::seq::{packet_sequence_len, seq_ge, seq_gt, seq_lt};
use super::types::TcpFlowState;

/// Stack-allocated buffer for TCP option bytes.
///
/// TCP options are at most 40 bytes (60-byte header – 20-byte fixed part).
/// Using a fixed-size array eliminates the `Vec::new()` heap allocation that
/// was previously incurred for every ACK or SYN-ACK built by the state machine.
struct TcpOptions {
    data: [u8; 40],
    len: usize,
}

impl TcpOptions {
    fn new() -> Self {
        Self { data: [0u8; 40], len: 0 }
    }

    #[inline]
    fn push(&mut self, b: u8) {
        assert!(self.len < 40, "TCP options overflow: max 40 bytes");
        self.data[self.len] = b;
        self.len += 1;
    }

    #[inline]
    fn extend_from_slice(&mut self, s: &[u8]) {
        let end = self.len + s.len();
        assert!(end <= 40, "TCP options overflow: max 40 bytes");
        self.data[self.len..end].copy_from_slice(s);
        self.len = end;
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

pub(in crate::tcp) fn build_flow_packet(
    state: &TcpFlowState,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let options = default_packet_options(state);
    build_flow_packet_with_options(
        state,
        sequence_number,
        acknowledgement_number,
        flags,
        options.as_slice(),
        payload,
    )
}

fn build_flow_packet_with_options(
    state: &TcpFlowState,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>> {
    build_response_packet_custom(
        state.key.version,
        state.key.remote_ip,
        state.key.client_ip,
        state.key.remote_port,
        state.key.client_port,
        sequence_number,
        acknowledgement_number,
        flags,
        advertised_receive_window(state),
        options,
        payload,
    )
}

pub(in crate::tcp) fn build_flow_ack_packet(
    state: &TcpFlowState,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u8,
) -> Result<Vec<u8>> {
    let options = ack_options(state);
    build_flow_packet_with_options(
        state,
        sequence_number,
        acknowledgement_number,
        flags,
        options.as_slice(),
        &[],
    )
}

pub(in crate::tcp) fn build_flow_syn_ack_packet(
    state: &TcpFlowState,
    server_isn: u32,
    acknowledgement_number: u32,
) -> Result<Vec<u8>> {
    let options = syn_ack_options(state);
    build_response_packet_custom(
        state.key.version,
        state.key.remote_ip,
        state.key.client_ip,
        state.key.remote_port,
        state.key.client_port,
        server_isn,
        acknowledgement_number,
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        advertised_receive_window(state),
        options.as_slice(),
        &[],
    )
}

fn syn_ack_options(state: &TcpFlowState) -> TcpOptions {
    let mut options = TcpOptions::new();
    options.push(2);
    options.push(4);
    options.extend_from_slice(
        &(MAX_SERVER_SEGMENT_PAYLOAD.min(u16::MAX as usize) as u16).to_be_bytes(),
    );
    if state.client_sack_permitted {
        options.extend_from_slice(&[4, 2]);
    }
    options.extend_from_slice(&[1, 3, 3, TCP_SERVER_WINDOW_SCALE]);
    append_timestamp_option(state, &mut options);
    pad_options(&mut options);
    options
}

fn ack_options(state: &TcpFlowState) -> TcpOptions {
    let mut options = default_packet_options(state);
    if !state.client_sack_permitted {
        pad_options(&mut options);
        return options;
    }

    let mut ranges = state
        .pending_client_segments
        .iter()
        .filter_map(|segment| {
            if !seq_gt(segment.sequence_number, state.rcv_nxt) {
                return None;
            }
            Some((
                segment.sequence_number,
                segment.sequence_number.wrapping_add(segment.payload.len() as u32),
            ))
        })
        .collect::<Vec<_>>();
    if ranges.is_empty() {
        pad_options(&mut options);
        return options;
    }

    ranges.sort_by(|(left_a, _), (left_b, _)| left_a.cmp(left_b));
    let mut merged = Vec::new();
    for (left, right) in ranges {
        match merged.last_mut() {
            Some((_, merged_right)) if !seq_gt(left, *merged_right) => {
                if seq_gt(right, *merged_right) {
                    *merged_right = right;
                }
            },
            _ => merged.push((left, right)),
        }
    }

    let block_count = max_sack_block_count(options.len()).min(merged.len());
    if block_count == 0 {
        pad_options(&mut options);
        return options;
    }
    options.push(5);
    options.push((2 + block_count * 8) as u8);
    for (left, right) in merged.into_iter().take(block_count) {
        options.extend_from_slice(&left.to_be_bytes());
        options.extend_from_slice(&right.to_be_bytes());
    }
    pad_options(&mut options);
    options
}

fn default_packet_options(state: &TcpFlowState) -> TcpOptions {
    let mut options = TcpOptions::new();
    append_timestamp_option(state, &mut options);
    pad_options(&mut options);
    options
}

fn append_timestamp_option(state: &TcpFlowState, options: &mut TcpOptions) {
    if !state.timestamps_enabled {
        return;
    }
    options.push(8);
    options.push(10);
    options.extend_from_slice(&current_timestamp_value(state).to_be_bytes());
    options.extend_from_slice(&state.recent_client_timestamp.unwrap_or(0).to_be_bytes());
}

fn current_timestamp_value(state: &TcpFlowState) -> u32 {
    state
        .server_timestamp_offset
        .wrapping_add(state.timestamps.created_at.elapsed().as_millis() as u32)
}

fn pad_options(options: &mut TcpOptions) {
    while !options.len().is_multiple_of(4) {
        options.push(1);
    }
}

fn max_sack_block_count(base_option_len: usize) -> usize {
    (1..=4)
        .rev()
        .find(|count| {
            let raw_len = base_option_len + 2 + count * 8;
            raw_len.next_multiple_of(4) <= 40
        })
        .unwrap_or(0)
}

fn advertised_receive_window(state: &TcpFlowState) -> u16 {
    let buffered_bytes = buffered_client_bytes(state);
    let available = state.receive_window_capacity.saturating_sub(buffered_bytes);
    let scaled = available >> TCP_SERVER_WINDOW_SCALE;
    scaled.min(u16::MAX as usize) as u16
}

pub(in crate::tcp) fn decode_client_window(packet: &ParsedTcpPacket, scale: u8) -> u32 {
    if (packet.flags & TCP_FLAG_SYN) != 0 {
        u32::from(packet.window_size)
    } else {
        u32::from(packet.window_size) << scale.min(14)
    }
}

pub(in crate::tcp) fn update_client_send_window(state: &mut TcpFlowState, packet: &ParsedTcpPacket) {
    let decoded_window = decode_client_window(packet, state.client_window_scale);
    let should_update = seq_gt(packet.sequence_number, state.client_window_update_seq)
        || (packet.sequence_number == state.client_window_update_seq
            && (seq_gt(packet.acknowledgement_number, state.client_window_update_ack)
                || (packet.acknowledgement_number == state.client_window_update_ack
                    && decoded_window > state.client_window)));
    if should_update || decoded_window == 0 {
        state.client_window = decoded_window;
        state.client_window_end = packet.acknowledgement_number.wrapping_add(decoded_window);
        state.client_window_update_seq = packet.sequence_number;
        state.client_window_update_ack = packet.acknowledgement_number;
    }
}

pub(in crate::tcp) fn send_window_remaining(state: &TcpFlowState) -> u32 {
    if seq_ge(state.server_seq, state.client_window_end) {
        0
    } else {
        state.client_window_end.wrapping_sub(state.server_seq)
    }
}

pub(in crate::tcp) fn buffered_client_bytes(state: &TcpFlowState) -> usize {
    state
        .pending_client_segments
        .iter()
        .map(|segment| segment.payload.len())
        .sum::<usize>()
        + state.pending_client_data.iter().map(Bytes::len).sum::<usize>()
}

pub(in crate::tcp) fn receive_window_end(state: &TcpFlowState) -> u32 {
    state.rcv_nxt.wrapping_add(
        state
            .receive_window_capacity
            .saturating_sub(buffered_client_bytes(state)) as u32,
    )
}

pub(in crate::tcp) fn packet_overlaps_receive_window(
    state: &TcpFlowState,
    packet: &ParsedTcpPacket,
) -> bool {
    let rcv_nxt = state.rcv_nxt;
    let rcv_wnd = receive_window_end(state).wrapping_sub(rcv_nxt);
    let seg_len = packet_sequence_len(packet);
    if rcv_wnd == 0 {
        return seg_len == 0 && packet.sequence_number == rcv_nxt;
    }

    if seg_len == 0 {
        return seq_ge(packet.sequence_number, rcv_nxt)
            && seq_lt(packet.sequence_number, rcv_nxt.wrapping_add(rcv_wnd));
    }

    let last = packet.sequence_number.wrapping_add(seg_len).wrapping_sub(1);
    (seq_ge(packet.sequence_number, rcv_nxt)
        && seq_lt(packet.sequence_number, rcv_nxt.wrapping_add(rcv_wnd)))
        || (seq_ge(last, rcv_nxt) && seq_lt(last, rcv_nxt.wrapping_add(rcv_wnd)))
}
