use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::{Mutex, Notify, watch};

use crate::config::TunTcpConfig;
use crate::metrics;
use crate::transport::TcpShadowsocksWriter;

use super::{
    MAX_SERVER_SEGMENT_PAYLOAD, ParsedTcpPacket, TCP_FAST_RETRANSMIT_DUP_ACKS, TCP_FLAG_ACK,
    TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_SYN, TCP_MAX_RTO, TCP_MIN_RTO, TCP_MIN_SSTHRESH,
    TCP_SERVER_WINDOW_SCALE, TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL,
    TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL, TcpFlowKey, build_response_packet_custom,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TcpFlowStatus {
    SynReceived,
    Established,
    CloseWait,
    FinWait1,
    FinWait2,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

pub(super) struct TcpFlowState {
    pub(super) id: u64,
    pub(super) key: TcpFlowKey,
    pub(super) uplink_index: usize,
    pub(super) uplink_name: String,
    pub(super) upstream_writer: Option<Arc<Mutex<TcpShadowsocksWriter>>>,
    pub(super) close_signal: watch::Sender<bool>,
    pub(super) maintenance_notify: Arc<Notify>,
    pub(super) status: TcpFlowStatus,
    pub(super) client_next_seq: u32,
    pub(super) client_window_scale: u8,
    pub(super) client_sack_permitted: bool,
    pub(super) client_max_segment_size: Option<u16>,
    pub(super) timestamps_enabled: bool,
    pub(super) recent_client_timestamp: Option<u32>,
    pub(super) server_timestamp_offset: u32,
    pub(super) client_window: u32,
    pub(super) client_window_end: u32,
    pub(super) client_window_update_seq: u32,
    pub(super) client_window_update_ack: u32,
    pub(super) server_seq: u32,
    pub(super) last_client_ack: u32,
    pub(super) duplicate_ack_count: u8,
    pub(super) receive_window_capacity: usize,
    pub(super) smoothed_rtt: Option<Duration>,
    pub(super) rttvar: Duration,
    pub(super) retransmission_timeout: Duration,
    pub(super) congestion_window: usize,
    pub(super) slow_start_threshold: usize,
    pub(super) pending_server_data: VecDeque<Vec<u8>>,
    pub(super) backlog_limit_exceeded_since: Option<Instant>,
    pub(super) last_ack_progress_at: Instant,
    pub(super) pending_client_data: VecDeque<Vec<u8>>,
    pub(super) unacked_server_segments: VecDeque<ServerSegment>,
    pub(super) pending_client_segments: Vec<BufferedClientSegment>,
    pub(super) server_fin_pending: bool,
    pub(super) zero_window_probe_backoff: Duration,
    pub(super) next_zero_window_probe_at: Option<Instant>,
    pub(super) reported_inflight_segments: usize,
    pub(super) reported_inflight_bytes: usize,
    pub(super) reported_pending_server_bytes: usize,
    pub(super) reported_buffered_client_segments: usize,
    pub(super) reported_zero_window: bool,
    pub(super) reported_backlog_pressure: bool,
    pub(super) reported_backlog_pressure_us: u64,
    pub(super) reported_ack_progress_stall: bool,
    pub(super) reported_ack_progress_stall_us: u64,
    pub(super) reported_active: bool,
    pub(super) reported_congestion_window: usize,
    pub(super) reported_slow_start_threshold: usize,
    pub(super) reported_retransmission_timeout_us: u64,
    pub(super) reported_smoothed_rtt_us: u64,
    pub(super) created_at: Instant,
    pub(super) status_since: Instant,
    pub(super) last_seen: Instant,
}

#[derive(Debug)]
pub(super) struct ClientSegmentView {
    pub(super) payload: Vec<u8>,
    pub(super) fin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BufferedClientSegment {
    pub(super) sequence_number: u32,
    pub(super) flags: u8,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub(super) struct ServerSegment {
    pub(super) sequence_number: u32,
    pub(super) acknowledgement_number: u32,
    pub(super) flags: u8,
    pub(super) payload: Vec<u8>,
    pub(super) sacked: bool,
    pub(super) last_sent: Instant,
    pub(super) first_sent: Instant,
    pub(super) retransmits: u32,
}

#[derive(Debug, Default)]
pub(super) struct ServerFlush {
    pub(super) data_packets: Vec<Vec<u8>>,
    pub(super) fin_packet: Option<Vec<u8>>,
    pub(super) probe_packet: Option<Vec<u8>>,
    pub(super) window_stalled: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ServerBacklogPressure {
    pub(super) exceeded: bool,
    pub(super) should_abort: bool,
    pub(super) pending_bytes: usize,
    pub(super) over_limit_ms: Option<u128>,
    pub(super) no_progress_ms: Option<u128>,
    pub(super) window_stalled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AckEffect {
    None,
    Advanced {
        bytes_acked: usize,
        rtt_sample: Option<Duration>,
    },
    Duplicate,
    DuplicateThresholdReached,
}

pub(super) fn build_flow_packet(
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
        &options,
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

pub(super) fn build_flow_ack_packet(
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
        &options,
        &[],
    )
}

pub(super) fn build_flow_syn_ack_packet(
    state: &TcpFlowState,
    server_isn: u32,
    acknowledgement_number: u32,
) -> Result<Vec<u8>> {
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
        &syn_ack_options(state),
        &[],
    )
}

fn syn_ack_options(state: &TcpFlowState) -> Vec<u8> {
    let mut options = Vec::new();
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

fn ack_options(state: &TcpFlowState) -> Vec<u8> {
    let mut options = default_packet_options(state);
    if !state.client_sack_permitted {
        pad_options(&mut options);
        return options;
    }

    let mut ranges = state
        .pending_client_segments
        .iter()
        .filter_map(|segment| {
            if !seq_gt(segment.sequence_number, state.client_next_seq) {
                return None;
            }
            Some((
                segment.sequence_number,
                segment
                    .sequence_number
                    .wrapping_add(segment.payload.len() as u32),
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
            }
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

fn default_packet_options(state: &TcpFlowState) -> Vec<u8> {
    let mut options = Vec::new();
    append_timestamp_option(state, &mut options);
    pad_options(&mut options);
    options
}

fn append_timestamp_option(state: &TcpFlowState, options: &mut Vec<u8>) {
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
        .wrapping_add(state.created_at.elapsed().as_millis() as u32)
}

fn pad_options(options: &mut Vec<u8>) {
    while options.len() % 4 != 0 {
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

pub(super) fn decode_client_window(packet: &ParsedTcpPacket, scale: u8) -> u32 {
    if (packet.flags & TCP_FLAG_SYN) != 0 {
        u32::from(packet.window_size)
    } else {
        u32::from(packet.window_size) << scale.min(14)
    }
}

pub(super) fn update_client_send_window(state: &mut TcpFlowState, packet: &ParsedTcpPacket) {
    let decoded_window = decode_client_window(packet, state.client_window_scale);
    let should_update = seq_gt(packet.sequence_number, state.client_window_update_seq)
        || (packet.sequence_number == state.client_window_update_seq
            && (seq_gt(
                packet.acknowledgement_number,
                state.client_window_update_ack,
            ) || (packet.acknowledgement_number == state.client_window_update_ack
                && decoded_window > state.client_window)));
    if should_update || decoded_window == 0 {
        state.client_window = decoded_window;
        state.client_window_end = packet.acknowledgement_number.wrapping_add(decoded_window);
        state.client_window_update_seq = packet.sequence_number;
        state.client_window_update_ack = packet.acknowledgement_number;
    }
}

fn send_window_remaining(state: &TcpFlowState) -> u32 {
    if seq_ge(state.server_seq, state.client_window_end) {
        0
    } else {
        state.client_window_end.wrapping_sub(state.server_seq)
    }
}

fn buffered_client_bytes(state: &TcpFlowState) -> usize {
    state
        .pending_client_segments
        .iter()
        .map(|segment| segment.payload.len())
        .sum::<usize>()
        + state
            .pending_client_data
            .iter()
            .map(Vec::len)
            .sum::<usize>()
}

pub(super) fn set_flow_status(state: &mut TcpFlowState, status: TcpFlowStatus) {
    if state.status != status {
        state.status = status;
        state.status_since = Instant::now();
    }
}

pub(super) fn client_fin_seen(status: TcpFlowStatus) -> bool {
    matches!(
        status,
        TcpFlowStatus::CloseWait
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck
            | TcpFlowStatus::TimeWait
            | TcpFlowStatus::Closed
    )
}

pub(super) fn server_fin_sent(status: TcpFlowStatus) -> bool {
    matches!(
        status,
        TcpFlowStatus::FinWait1
            | TcpFlowStatus::FinWait2
            | TcpFlowStatus::Closing
            | TcpFlowStatus::LastAck
            | TcpFlowStatus::TimeWait
            | TcpFlowStatus::Closed
    )
}

pub(super) fn server_fin_awaiting_ack(status: TcpFlowStatus) -> bool {
    matches!(
        status,
        TcpFlowStatus::FinWait1 | TcpFlowStatus::Closing | TcpFlowStatus::LastAck
    )
}

pub(super) fn transition_on_client_fin(state: &mut TcpFlowState) {
    match state.status {
        TcpFlowStatus::SynReceived | TcpFlowStatus::Established => {
            set_flow_status(state, TcpFlowStatus::CloseWait);
        }
        TcpFlowStatus::FinWait1 => {
            set_flow_status(state, TcpFlowStatus::Closing);
        }
        TcpFlowStatus::FinWait2 => {
            set_flow_status(state, TcpFlowStatus::TimeWait);
        }
        TcpFlowStatus::CloseWait
        | TcpFlowStatus::Closing
        | TcpFlowStatus::LastAck
        | TcpFlowStatus::TimeWait
        | TcpFlowStatus::Closed => {}
    }
}

pub(super) fn transition_on_server_fin_ack(state: &mut TcpFlowState) -> bool {
    match state.status {
        TcpFlowStatus::FinWait1 => {
            set_flow_status(state, TcpFlowStatus::FinWait2);
            false
        }
        TcpFlowStatus::Closing => {
            set_flow_status(state, TcpFlowStatus::TimeWait);
            false
        }
        TcpFlowStatus::LastAck => {
            set_flow_status(state, TcpFlowStatus::Closed);
            true
        }
        TcpFlowStatus::SynReceived
        | TcpFlowStatus::Established
        | TcpFlowStatus::CloseWait
        | TcpFlowStatus::FinWait2
        | TcpFlowStatus::TimeWait
        | TcpFlowStatus::Closed => false,
    }
}

pub(super) fn reset_zero_window_persist(state: &mut TcpFlowState) {
    state.zero_window_probe_backoff = TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL;
    state.next_zero_window_probe_at = None;
}

pub(super) fn note_recent_client_timestamp(state: &mut TcpFlowState, timestamp_value: Option<u32>) {
    if state.timestamps_enabled {
        if let Some(timestamp_value) = timestamp_value {
            state.recent_client_timestamp = Some(timestamp_value);
        }
    }
}

fn receive_window_end(state: &TcpFlowState) -> u32 {
    state.client_next_seq.wrapping_add(
        state
            .receive_window_capacity
            .saturating_sub(buffered_client_bytes(state)) as u32,
    )
}

pub(super) fn trim_packet_to_receive_window(
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

pub(super) fn normalize_client_segment(
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
        Vec::new()
    } else {
        payload[overlap..].to_vec()
    };

    let fin = if (flags & TCP_FLAG_FIN) == 0 {
        false
    } else {
        overlap <= original_payload_len
    };

    ClientSegmentView { payload, fin }
}

pub(super) fn queue_future_segment(
    pending_segments: &mut Vec<BufferedClientSegment>,
    packet: &ParsedTcpPacket,
) {
    if packet.payload.is_empty() && (packet.flags & TCP_FLAG_FIN) == 0 {
        return;
    }
    let candidate = BufferedClientSegment {
        sequence_number: packet.sequence_number,
        flags: packet.flags & (TCP_FLAG_FIN | TCP_FLAG_ACK),
        payload: packet.payload.clone(),
    };
    if pending_segments
        .iter()
        .any(|existing| existing == &candidate)
    {
        return;
    }
    pending_segments.push(candidate);
}

pub(super) fn queue_future_segment_with_recv_window(
    state: &mut TcpFlowState,
    packet: &ParsedTcpPacket,
) {
    let Some(trimmed) = trim_packet_to_receive_window(state, packet) else {
        return;
    };
    queue_future_segment(&mut state.pending_client_segments, &trimmed);
}

pub(super) fn exceeds_client_reassembly_limits(
    state: &TcpFlowState,
    config: &TunTcpConfig,
) -> bool {
    state.pending_client_segments.len() > config.max_buffered_client_segments
        || buffered_client_bytes(state) > config.max_buffered_client_bytes
}

pub(super) fn assess_server_backlog_pressure(
    state: &mut TcpFlowState,
    config: &TunTcpConfig,
    now: Instant,
    window_stalled: bool,
) -> ServerBacklogPressure {
    let pending_bytes = pending_server_bytes(state);
    if pending_bytes <= config.max_pending_server_bytes {
        state.backlog_limit_exceeded_since = None;
        return ServerBacklogPressure {
            pending_bytes,
            window_stalled,
            ..ServerBacklogPressure::default()
        };
    }

    let first_exceeded_at = *state.backlog_limit_exceeded_since.get_or_insert(now);
    let over_limit_for = now.saturating_duration_since(first_exceeded_at);
    let no_progress_for = now.saturating_duration_since(state.last_ack_progress_at);
    let hard_limit = config
        .max_pending_server_bytes
        .saturating_mul(config.backlog_hard_limit_multiplier);
    let should_abort = pending_bytes > hard_limit
        || over_limit_for >= config.backlog_abort_grace
        || (window_stalled && no_progress_for >= config.backlog_no_progress_abort);

    ServerBacklogPressure {
        exceeded: true,
        should_abort,
        pending_bytes,
        over_limit_ms: Some(over_limit_for.as_millis()),
        no_progress_ms: Some(no_progress_for.as_millis()),
        window_stalled,
    }
}

pub(super) fn retransmit_budget_exhausted(state: &TcpFlowState, config: &TunTcpConfig) -> bool {
    state
        .unacked_server_segments
        .iter()
        .any(|segment| segment.retransmits >= config.max_retransmits)
}

pub(super) fn drain_ready_buffered_segments(
    expected_seq: &mut u32,
    pending_segments: &mut Vec<BufferedClientSegment>,
    pending_payload: &mut Vec<u8>,
) -> bool {
    loop {
        let Some(index) = find_next_ready_segment_index(*expected_seq, pending_segments) else {
            return false;
        };
        let segment = pending_segments.remove(index);
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

pub(super) fn drain_ready_buffered_segments_from_state(
    state: &mut TcpFlowState,
    pending_payload: &mut Vec<u8>,
) -> bool {
    drain_ready_buffered_segments(
        &mut state.client_next_seq,
        &mut state.pending_client_segments,
        pending_payload,
    )
}

pub(super) fn apply_client_segment(
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

fn find_next_ready_segment_index(
    expected_seq: u32,
    pending_segments: &[BufferedClientSegment],
) -> Option<usize> {
    let mut best: Option<(usize, u32)> = None;
    for (index, segment) in pending_segments.iter().enumerate() {
        if seq_gt(segment.sequence_number, expected_seq) {
            continue;
        }
        if best
            .as_ref()
            .map(|(_, best_seq)| seq_lt(segment.sequence_number, *best_seq))
            .unwrap_or(true)
        {
            best = Some((index, segment.sequence_number));
        }
    }
    best.map(|(index, _)| index)
}

pub(super) fn is_duplicate_syn(packet: &ParsedTcpPacket, expected_seq: u32) -> bool {
    (packet.flags & TCP_FLAG_SYN) != 0
        && (packet.flags & TCP_FLAG_ACK) == 0
        && packet.payload.is_empty()
        && packet.sequence_number == expected_seq.wrapping_sub(1)
}

pub(super) fn seq_lt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) < 0
}

pub(super) fn seq_gt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) > 0
}

pub(super) fn seq_ge(lhs: u32, rhs: u32) -> bool {
    !seq_lt(lhs, rhs)
}

fn seq_le(lhs: u32, rhs: u32) -> bool {
    !seq_gt(lhs, rhs)
}

pub(super) fn timestamp_lt(lhs: u32, rhs: u32) -> bool {
    (lhs.wrapping_sub(rhs) as i32) < 0
}

pub(super) fn packet_sequence_len(packet: &ParsedTcpPacket) -> u32 {
    packet.payload.len() as u32
        + u32::from((packet.flags & TCP_FLAG_SYN) != 0)
        + u32::from((packet.flags & TCP_FLAG_FIN) != 0)
}

pub(super) fn packet_overlaps_receive_window(
    state: &TcpFlowState,
    packet: &ParsedTcpPacket,
) -> bool {
    let rcv_nxt = state.client_next_seq;
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

pub(super) fn process_server_ack(
    state: &mut TcpFlowState,
    acknowledgement_number: u32,
    sack_blocks: &[(u32, u32)],
) -> AckEffect {
    if state.unacked_server_segments.is_empty() {
        state.last_client_ack = acknowledgement_number;
        state.duplicate_ack_count = 0;
        return AckEffect::None;
    }

    for segment in &mut state.unacked_server_segments {
        let segment_end = segment
            .sequence_number
            .wrapping_add(server_segment_len(segment) as u32);
        if sack_blocks.iter().any(|(left, right)| {
            seq_le(*left, segment.sequence_number) && seq_ge(*right, segment_end)
        }) {
            segment.sacked = true;
        }
    }

    if seq_gt(acknowledgement_number, state.last_client_ack) {
        state.last_client_ack = acknowledgement_number;
        state.duplicate_ack_count = 0;
        let mut bytes_acked = 0usize;
        let mut rtt_sample = None;
        while let Some(segment) = state.unacked_server_segments.front() {
            let segment_end = segment
                .sequence_number
                .wrapping_add(server_segment_len(segment) as u32);
            if seq_ge(acknowledgement_number, segment_end) {
                let segment = state
                    .unacked_server_segments
                    .pop_front()
                    .expect("front exists");
                bytes_acked = bytes_acked.saturating_add(server_segment_len(&segment));
                if segment.retransmits == 0 {
                    rtt_sample = Some(segment.first_sent.elapsed());
                }
            } else {
                break;
            }
        }
        AckEffect::Advanced {
            bytes_acked,
            rtt_sample,
        }
    } else if acknowledgement_number == state.last_client_ack {
        state.duplicate_ack_count = state.duplicate_ack_count.saturating_add(1);
        if state.duplicate_ack_count >= TCP_FAST_RETRANSMIT_DUP_ACKS {
            state.duplicate_ack_count = 0;
            AckEffect::DuplicateThresholdReached
        } else {
            AckEffect::Duplicate
        }
    } else {
        AckEffect::None
    }
}

fn highest_sacked_end(state: &TcpFlowState) -> Option<u32> {
    state
        .unacked_server_segments
        .iter()
        .filter(|segment| segment.sacked)
        .map(|segment| {
            segment
                .sequence_number
                .wrapping_add(server_segment_len(segment) as u32)
        })
        .max_by(|lhs, rhs| lhs.cmp(rhs))
}

fn preferred_retransmit_index(state: &TcpFlowState) -> Option<usize> {
    if let Some(highest_sacked_end) = highest_sacked_end(state) {
        if let Some(index) = state.unacked_server_segments.iter().position(|segment| {
            !segment.sacked && seq_lt(segment.sequence_number, highest_sacked_end)
        }) {
            return Some(index);
        }
    }

    state
        .unacked_server_segments
        .iter()
        .position(|segment| !segment.sacked)
        .or_else(|| (!state.unacked_server_segments.is_empty()).then_some(0))
}

fn congestion_window_remaining(state: &TcpFlowState) -> usize {
    state
        .congestion_window
        .saturating_sub(bytes_in_flight(&state.unacked_server_segments))
}

fn current_retransmission_timeout(state: &TcpFlowState) -> Duration {
    state.retransmission_timeout
}

fn update_rtt_estimator(state: &mut TcpFlowState, sample: Duration) {
    let sample_us = sample.as_micros() as f64;
    match state.smoothed_rtt {
        Some(smoothed_rtt) => {
            let srtt_us = smoothed_rtt.as_micros() as f64;
            let rttvar_us = state.rttvar.as_micros() as f64;
            let new_rttvar_us = 0.75 * rttvar_us + 0.25 * (srtt_us - sample_us).abs();
            let new_srtt_us = 0.875 * srtt_us + 0.125 * sample_us;
            state.smoothed_rtt = Some(Duration::from_micros(new_srtt_us.max(1.0) as u64));
            state.rttvar = Duration::from_micros(new_rttvar_us.max(1.0) as u64);
        }
        None => {
            state.smoothed_rtt = Some(sample);
            state.rttvar = sample / 2;
        }
    }

    let srtt = state.smoothed_rtt.unwrap_or(sample);
    let rto = srtt
        .saturating_add(state.rttvar.saturating_mul(4))
        .clamp(TCP_MIN_RTO, TCP_MAX_RTO);
    state.retransmission_timeout = rto;
}

pub(super) fn note_ack_progress(
    state: &mut TcpFlowState,
    bytes_acked: usize,
    rtt_sample: Option<Duration>,
) {
    if let Some(sample) = rtt_sample {
        update_rtt_estimator(state, sample);
    }
    if bytes_acked == 0 {
        return;
    }

    state.last_ack_progress_at = Instant::now();

    if state.congestion_window < state.slow_start_threshold {
        state.congestion_window = state.congestion_window.saturating_add(bytes_acked);
    } else {
        let additive =
            ((MAX_SERVER_SEGMENT_PAYLOAD * bytes_acked) / state.congestion_window).max(1);
        state.congestion_window = state.congestion_window.saturating_add(additive);
    }
}

pub(super) fn note_congestion_event(state: &mut TcpFlowState, timeout: bool) {
    let inflight = bytes_in_flight(&state.unacked_server_segments);
    state.slow_start_threshold = (inflight / 2).max(TCP_MIN_SSTHRESH);
    state.congestion_window = if timeout {
        MAX_SERVER_SEGMENT_PAYLOAD
    } else {
        state.slow_start_threshold
    };
    if timeout {
        state.retransmission_timeout = current_retransmission_timeout(state)
            .saturating_mul(2)
            .clamp(TCP_MIN_RTO, TCP_MAX_RTO);
    }
}

fn flush_server_data(state: &mut TcpFlowState) -> Result<Vec<Vec<u8>>> {
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
        let payload = front.drain(..payload_len).collect::<Vec<_>>();
        if front.is_empty() {
            state.pending_server_data.pop_front();
        }

        let sequence_number = state.server_seq;
        let acknowledgement_number = state.client_next_seq;
        let packet = build_flow_packet(
            state,
            sequence_number,
            acknowledgement_number,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            &payload,
        )?;
        state.server_seq = state.server_seq.wrapping_add(payload.len() as u32);
        state.unacked_server_segments.push_back(ServerSegment {
            sequence_number,
            acknowledgement_number,
            flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
            payload,
            sacked: false,
            last_sent: Instant::now(),
            first_sent: Instant::now(),
            retransmits: 0,
        });
        reset_zero_window_persist(state);
        packets.push(packet);
        available_window =
            send_window_remaining(state).min(congestion_window_remaining(state) as u32);
    }

    Ok(packets)
}

fn server_max_segment_payload(state: &TcpFlowState) -> usize {
    state
        .client_max_segment_size
        .map(|mss| usize::from(mss))
        .unwrap_or(MAX_SERVER_SEGMENT_PAYLOAD)
        .clamp(1, MAX_SERVER_SEGMENT_PAYLOAD)
}

pub(super) fn flush_server_output(state: &mut TcpFlowState) -> Result<ServerFlush> {
    if state.status == TcpFlowStatus::SynReceived {
        return Ok(ServerFlush::default());
    }
    let data_packets = flush_server_data(state)?;
    let window_stalled = send_window_remaining(state) == 0 && !state.pending_server_data.is_empty();
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
        || matches!(
            state.status,
            TcpFlowStatus::Closed | TcpFlowStatus::TimeWait
        )
    {
        return Ok(None);
    }

    let packet = build_flow_packet(
        state,
        state.server_seq,
        state.client_next_seq,
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
        }
        TcpFlowStatus::FinWait1
        | TcpFlowStatus::FinWait2
        | TcpFlowStatus::Closing
        | TcpFlowStatus::LastAck
        | TcpFlowStatus::TimeWait
        | TcpFlowStatus::Closed => {}
    }
    state.unacked_server_segments.push_back(ServerSegment {
        sequence_number,
        acknowledgement_number: state.client_next_seq,
        flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
        payload: Vec::new(),
        sacked: false,
        last_sent: Instant::now(),
        first_sent: Instant::now(),
        retransmits: 0,
    });
    Ok(Some(packet))
}

pub(super) fn maybe_emit_zero_window_probe(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
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
        state.client_next_seq,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        &[probe_byte],
    )?;
    let current = state.zero_window_probe_backoff;
    state.next_zero_window_probe_at = Some(now + current);
    state.zero_window_probe_backoff =
        (current.saturating_mul(2)).min(TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL);
    Ok(Some(packet))
}

pub(super) fn retransmit_oldest_unacked_packet(
    state: &mut TcpFlowState,
) -> Result<Option<Vec<u8>>> {
    let index = preferred_retransmit_index(state);
    let Some(index) = index else {
        return Ok(None);
    };
    let (sequence_number, acknowledgement_number, flags, payload) = {
        let segment = &mut state.unacked_server_segments[index];
        segment.last_sent = Instant::now();
        segment.retransmits = segment.retransmits.saturating_add(1);
        (
            segment.sequence_number,
            segment.acknowledgement_number,
            segment.flags,
            segment.payload.clone(),
        )
    };
    Ok(Some(build_flow_packet(
        state,
        sequence_number,
        state.client_next_seq.max(acknowledgement_number),
        flags,
        &payload,
    )?))
}

pub(super) fn retransmit_due_segment(state: &mut TcpFlowState) -> Result<Option<Vec<u8>>> {
    let Some(index) = preferred_retransmit_index(state)
        .filter(|index| {
            state.unacked_server_segments[*index].last_sent.elapsed()
                >= current_retransmission_timeout(state)
        })
        .or_else(|| {
            let rto = current_retransmission_timeout(state);
            state
                .unacked_server_segments
                .iter()
                .position(|segment| segment.last_sent.elapsed() >= rto)
        })
    else {
        return Ok(None);
    };
    let (sequence_number, acknowledgement_number, flags, payload) = {
        let segment = &mut state.unacked_server_segments[index];
        segment.last_sent = Instant::now();
        segment.retransmits = segment.retransmits.saturating_add(1);
        (
            segment.sequence_number,
            segment.acknowledgement_number,
            segment.flags,
            segment.payload.clone(),
        )
    };
    Ok(Some(build_flow_packet(
        state,
        sequence_number,
        state.client_next_seq.max(acknowledgement_number),
        flags,
        &payload,
    )?))
}

fn bytes_in_flight(segments: &VecDeque<ServerSegment>) -> usize {
    segments.iter().map(server_segment_len).sum()
}

fn server_segment_len(segment: &ServerSegment) -> usize {
    segment.payload.len()
        + usize::from((segment.flags & TCP_FLAG_SYN) != 0)
        + usize::from((segment.flags & TCP_FLAG_FIN) != 0)
}

fn pending_server_bytes(state: &TcpFlowState) -> usize {
    state.pending_server_data.iter().map(Vec::len).sum()
}

pub(super) fn sync_flow_metrics(state: &mut TcpFlowState) {
    let inflight_segments = state.unacked_server_segments.len();
    let inflight_bytes = bytes_in_flight(&state.unacked_server_segments);
    let pending_server_bytes = pending_server_bytes(state);
    let buffered_client_segments =
        state.pending_client_segments.len() + state.pending_client_data.len();
    let zero_window = state.client_window == 0 && pending_server_bytes > 0;
    let backlog_pressure = state.backlog_limit_exceeded_since.is_some();
    let backlog_pressure_us = state
        .backlog_limit_exceeded_since
        .map(|since| since.elapsed().as_micros() as u64)
        .unwrap_or(0);
    let ack_progress_stall =
        pending_server_bytes > 0 && state.last_ack_progress_at.elapsed() >= Duration::from_secs(1);
    let ack_progress_stall_us = if pending_server_bytes > 0 {
        state.last_ack_progress_at.elapsed().as_micros() as u64
    } else {
        0
    };
    let congestion_window = state.congestion_window;
    let slow_start_threshold = state.slow_start_threshold;
    let retransmission_timeout_us = state.retransmission_timeout.as_micros() as u64;
    let smoothed_rtt_us = state
        .smoothed_rtt
        .map(|duration| duration.as_micros() as u64)
        .unwrap_or(0);

    let uplink = state.uplink_name.as_str();
    if !state.reported_active {
        metrics::add_tun_tcp_flows_active(uplink, 1);
        state.reported_active = true;
    }
    apply_usize_gauge_delta(
        uplink,
        inflight_segments,
        &mut state.reported_inflight_segments,
        metrics::add_tun_tcp_inflight_segments,
    );
    apply_usize_gauge_delta(
        uplink,
        inflight_bytes,
        &mut state.reported_inflight_bytes,
        metrics::add_tun_tcp_inflight_bytes,
    );
    apply_usize_gauge_delta(
        uplink,
        pending_server_bytes,
        &mut state.reported_pending_server_bytes,
        metrics::add_tun_tcp_pending_server_bytes,
    );
    apply_usize_gauge_delta(
        uplink,
        buffered_client_segments,
        &mut state.reported_buffered_client_segments,
        metrics::add_tun_tcp_buffered_client_segments,
    );
    if zero_window != state.reported_zero_window {
        metrics::add_tun_tcp_zero_window_flows(uplink, if zero_window { 1 } else { -1 });
        state.reported_zero_window = zero_window;
    }
    if backlog_pressure != state.reported_backlog_pressure {
        metrics::add_tun_tcp_backlog_pressure_flows(uplink, if backlog_pressure { 1 } else { -1 });
        state.reported_backlog_pressure = backlog_pressure;
    }
    apply_u64_seconds_gauge_delta(
        uplink,
        backlog_pressure_us,
        &mut state.reported_backlog_pressure_us,
        metrics::add_tun_tcp_backlog_pressure_seconds,
    );
    if ack_progress_stall != state.reported_ack_progress_stall {
        metrics::add_tun_tcp_ack_progress_stall_flows(
            uplink,
            if ack_progress_stall { 1 } else { -1 },
        );
        state.reported_ack_progress_stall = ack_progress_stall;
    }
    apply_u64_seconds_gauge_delta(
        uplink,
        ack_progress_stall_us,
        &mut state.reported_ack_progress_stall_us,
        metrics::add_tun_tcp_ack_progress_stall_seconds,
    );
    apply_usize_gauge_delta(
        uplink,
        congestion_window,
        &mut state.reported_congestion_window,
        metrics::add_tun_tcp_congestion_window_bytes,
    );
    apply_usize_gauge_delta(
        uplink,
        slow_start_threshold,
        &mut state.reported_slow_start_threshold,
        metrics::add_tun_tcp_slow_start_threshold_bytes,
    );
    apply_u64_seconds_gauge_delta(
        uplink,
        retransmission_timeout_us,
        &mut state.reported_retransmission_timeout_us,
        metrics::add_tun_tcp_retransmission_timeout_seconds,
    );
    apply_u64_seconds_gauge_delta(
        uplink,
        smoothed_rtt_us,
        &mut state.reported_smoothed_rtt_us,
        metrics::add_tun_tcp_smoothed_rtt_seconds,
    );
}

pub(super) fn clear_flow_metrics(state: &mut TcpFlowState) {
    let uplink = state.uplink_name.as_str();
    if state.reported_active {
        metrics::add_tun_tcp_flows_active(uplink, -1);
        state.reported_active = false;
    }
    if state.reported_inflight_segments != 0 {
        metrics::add_tun_tcp_inflight_segments(uplink, -(state.reported_inflight_segments as i64));
        state.reported_inflight_segments = 0;
    }
    if state.reported_inflight_bytes != 0 {
        metrics::add_tun_tcp_inflight_bytes(uplink, -(state.reported_inflight_bytes as i64));
        state.reported_inflight_bytes = 0;
    }
    if state.reported_pending_server_bytes != 0 {
        metrics::add_tun_tcp_pending_server_bytes(
            uplink,
            -(state.reported_pending_server_bytes as i64),
        );
        state.reported_pending_server_bytes = 0;
    }
    if state.reported_buffered_client_segments != 0 {
        metrics::add_tun_tcp_buffered_client_segments(
            uplink,
            -(state.reported_buffered_client_segments as i64),
        );
        state.reported_buffered_client_segments = 0;
    }
    if state.reported_zero_window {
        metrics::add_tun_tcp_zero_window_flows(uplink, -1);
        state.reported_zero_window = false;
    }
    if state.reported_backlog_pressure {
        metrics::add_tun_tcp_backlog_pressure_flows(uplink, -1);
        state.reported_backlog_pressure = false;
    }
    if state.reported_backlog_pressure_us != 0 {
        metrics::add_tun_tcp_backlog_pressure_seconds(
            uplink,
            -(state.reported_backlog_pressure_us as f64) / 1_000_000.0,
        );
        state.reported_backlog_pressure_us = 0;
    }
    if state.reported_ack_progress_stall {
        metrics::add_tun_tcp_ack_progress_stall_flows(uplink, -1);
        state.reported_ack_progress_stall = false;
    }
    if state.reported_ack_progress_stall_us != 0 {
        metrics::add_tun_tcp_ack_progress_stall_seconds(
            uplink,
            -(state.reported_ack_progress_stall_us as f64) / 1_000_000.0,
        );
        state.reported_ack_progress_stall_us = 0;
    }
    if state.reported_congestion_window != 0 {
        metrics::add_tun_tcp_congestion_window_bytes(
            uplink,
            -(state.reported_congestion_window as i64),
        );
        state.reported_congestion_window = 0;
    }
    if state.reported_slow_start_threshold != 0 {
        metrics::add_tun_tcp_slow_start_threshold_bytes(
            uplink,
            -(state.reported_slow_start_threshold as i64),
        );
        state.reported_slow_start_threshold = 0;
    }
    if state.reported_retransmission_timeout_us != 0 {
        metrics::add_tun_tcp_retransmission_timeout_seconds(
            uplink,
            -((state.reported_retransmission_timeout_us as f64) / 1_000_000.0),
        );
        state.reported_retransmission_timeout_us = 0;
    }
    if state.reported_smoothed_rtt_us != 0 {
        metrics::add_tun_tcp_smoothed_rtt_seconds(
            uplink,
            -((state.reported_smoothed_rtt_us as f64) / 1_000_000.0),
        );
        state.reported_smoothed_rtt_us = 0;
    }
}

fn apply_usize_gauge_delta(
    uplink: &str,
    current: usize,
    reported: &mut usize,
    record: fn(&str, i64),
) {
    let delta = current as i64 - *reported as i64;
    if delta != 0 {
        record(uplink, delta);
        *reported = current;
    }
}

fn apply_u64_seconds_gauge_delta(
    uplink: &str,
    current: u64,
    reported: &mut u64,
    record: fn(&str, f64),
) {
    let delta = current as f64 - *reported as f64;
    if delta != 0.0 {
        record(uplink, delta / 1_000_000.0);
        *reported = current;
    }
}
