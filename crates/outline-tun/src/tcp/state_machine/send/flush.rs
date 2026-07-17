use std::time::Instant;

use anyhow::Result;
use bytes::{Bytes, BytesMut};

use super::super::super::{
    GSO_MAX_SUPER_SEGMENT_PAYLOAD, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH,
    TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL,
};

/// Upper bound on the number of `Bytes` chunks coalesced into one vectored
/// downlink write. The write is `[vnet?, header, chunk0, …]`, so this keeps the
/// `iovec` count far below `IOV_MAX` (1024). A super-segment that would need
/// more chunks is simply emitted shorter — correctness is unaffected, the
/// remainder flushes next iteration.
const MAX_WRITE_PAYLOAD_CHUNKS: usize = 128;
use super::super::bbr::{pacing_active, pacing_release_at, refill_pacing_credit};
use super::super::congestion::{congestion_window_remaining, server_max_segment_payload};
use super::super::packets::{
    build_flow_data_header, build_flow_packet, build_gso_flow_header, send_window_remaining,
};
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
    //
    // It bounds the refill's *latency*, though, not its size: consecutive
    // flushes still land 0.5–4 ms apart (ACK aggregation, and the ~1 ms timer
    // behind the pacing wakeup), and whatever accrued past the bucket ceiling in
    // that gap is gone. Sizing that ceiling off the rate is what keeps this
    // ACK clock from becoming the ceiling itself.
    let now = Instant::now();
    refill_pacing_credit(state, now);
    let pacing = pacing_active(state);
    state.bbr.pacing_next_at = None;

    let mut packets = Vec::new();
    // Both bounds shrink by exactly `payload_len` per iteration: `server_seq`
    // advances (so `send_window_remaining` drops) and the pipe grows (so
    // `congestion_window_remaining` drops), while cwnd / the BBR cap / the peer
    // window are constant across a flush (no ACK is processed in this loop). So
    // compute the send window once and decrement it per write instead of
    // recomputing `congestion_window_remaining` — an O(pipe) call — after every
    // emitted segment (the source of the quadratic flush).
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
        let payload_len: usize = payload.iter().map(Bytes::len).sum();
        // App-limited, as `tcp_rate_check_app_limited` defines it: the queue ran
        // dry *and* there was still window to send into — our supply, not the
        // window, is what ended this flight, so the delivery-rate sample
        // measures us rather than the path and may only raise BtlBw.
        //
        // The window half is not optional. `pending.is_empty()` alone marks most
        // segments of a bandwidth-limited bulk transfer too: the reader hands
        // over one chunk, the flush ships it, and the queue is empty again — so
        // the flag was set on flights that were in fact congestion-limited and
        // whose samples must be allowed to lower BtlBw. Copying canonical BBR's
        // app-limited rules onto that broken flag is what sank 3d0d495 (STARTUP
        // never ended, the stack offered the last hop 2.9x its measured
        // bandwidth, and the loss cap collapsed onto its floor). When the window
        // is what stopped the flight, the flight is congestion-limited: not
        // app-limited, whatever the queue looks like afterwards.
        let app_limited =
            state.pending_server_data.is_empty() && (available_window as usize) > payload_len;

        let sequence_number = state.server_seq;
        let acknowledgement_number = state.rcv_nxt;
        let flags = TCP_FLAG_ACK | TCP_FLAG_PSH;

        // The wire packet is one super-segment (TSO) or one MSS packet, but the
        // retransmit/SACK/BBR scoreboard always tracks per-MSS segments so a
        // loss inside a super-segment is recovered at MSS granularity. Only the
        // IP/TCP header is built here; the payload chunks are carried by
        // reference (the same owned `Bytes` upstream produced) and written
        // vectored — never coalesced into a contiguous buffer.
        let (header, vnet) = if state.gso_enabled && payload_len > max_payload_per_segment {
            // Partial (TSO) checksum needs only the length; the kernel finalises
            // each MSS segment, so the payload bytes are never read here.
            let (header, vnet) = build_gso_flow_header(
                state,
                sequence_number,
                acknowledgement_number,
                flags,
                max_payload_per_segment as u16,
                payload_len,
            )?;
            (header, Some(vnet))
        } else {
            // Full checksum folds the payload chunks in order without copying.
            let parts: Vec<&[u8]> = payload.iter().map(Bytes::as_ref).collect();
            let header = build_flow_data_header(
                state,
                sequence_number,
                acknowledgement_number,
                flags,
                &parts,
            )?;
            (header, None)
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
        packets.push(ServerDataPacket { header, payload, vnet });
        available_window = available_window.saturating_sub(payload_len as u32);
    }

    Ok(packets)
}

/// Take up to `target` bytes off the pending downlink queue as a list of
/// zero-copy `Bytes` chunks — each a `split_to` slice of a queued buffer, never
/// a copy. One chunk on the fast path (the first buffer covers `target`);
/// several when a TSO super-segment spans multiple upstream reads. Capped at
/// [`MAX_WRITE_PAYLOAD_CHUNKS`] so the vectored write stays well under
/// `IOV_MAX`; hitting the cap just emits a shorter super-segment.
fn take_pending_server_payload(state: &mut TcpFlowState, target: usize) -> Vec<Bytes> {
    let mut chunks = Vec::new();
    let mut collected = 0;
    while collected < target && chunks.len() < MAX_WRITE_PAYLOAD_CHUNKS {
        let Some(front) = state.pending_server_data.front_mut() else {
            break;
        };
        if front.is_empty() {
            state.pending_server_data.pop_front();
            continue;
        }
        let take = front.len().min(target - collected);
        let piece = front.split_to(take);
        if front.is_empty() {
            state.pending_server_data.pop_front();
        }
        collected += take;
        state.pending_server_bytes_total -= take;
        chunks.push(piece);
    }
    chunks
}

/// Register the just-sent payload `chunks` on the retransmit scoreboard as
/// per-MSS segments (so a hole inside a TSO super-segment is retransmitted at
/// MSS granularity). Each segment's payload is a [`slice_chunks`] view — a
/// zero-copy `Bytes::slice` unless the MSS boundary straddles a chunk boundary.
/// All segments share the send instant and delivered snapshot — they left the
/// stack in one write.
#[allow(clippy::too_many_arguments)]
fn push_unacked_segments(
    state: &mut TcpFlowState,
    start_sequence: u32,
    acknowledgement_number: u32,
    flags: u8,
    chunks: &[Bytes],
    mss: usize,
    app_limited: bool,
) {
    let sent_at = Instant::now();
    // Sending into an empty pipe starts a new flight. Restart both anchors from
    // now: the flight's send interval is measured from here, and `delivered_at`
    // must not still point at an ACK from before an idle gap — that would stretch
    // the rate interval across the whole gap and under-read the path. Canonical
    // BBR does the same in `tcp_rate_skb_sent` when `!tp->packets_out`.
    if state.pipe_segments == 0 {
        state.first_tx_mstamp = sent_at;
        state.bbr.delivered_at = sent_at;
    }
    let delivered_snapshot = state.bbr.delivered;
    let delivered_at_snapshot = state.bbr.delivered_at;
    let first_tx_snapshot = state.first_tx_mstamp;
    let total: usize = chunks.iter().map(Bytes::len).sum();
    let mut offset = 0;
    let mut sequence_number = start_sequence;
    while offset < total {
        let end = (offset + mss).min(total);
        let segment_len = end - offset;
        state.unacked_server_segments.push_back(ServerSegment {
            sequence_number,
            acknowledgement_number,
            flags,
            payload: slice_chunks(chunks, offset, end),
            last_sent: sent_at,
            first_sent: sent_at,
            retransmits: 0,
            rto_retransmits: 0,
            fast_retransmit_epoch: 0,
            delivered_snapshot,
            delivered_at_snapshot,
            first_tx_snapshot,
            app_limited,
        });
        // Freshly-sent data sits above every SACKed range, so it enters the
        // pipe un-SACKed (`flags` carry no SYN/FIN here, so its length equals
        // its payload). Keep the running pipe counters in step with the O(1)
        // reads in `flush_server_data` / `sync_flow_metrics`.
        state.pipe_bytes += segment_len;
        state.pipe_segments += 1;
        sequence_number = sequence_number.wrapping_add(segment_len as u32);
        offset = end;
    }
    // `sent_at` (== now) is >= every earlier send instant, so it is the earliest
    // only when nothing un-SACKed was in flight before this push.
    state.earliest_unsacked_sent.get_or_insert(sent_at);
}

/// The `[start, end)` byte range of the logical payload formed by concatenating
/// `chunks`, returned as a single `Bytes`. Zero-copy (`Bytes::slice`) when the
/// range lies within one chunk; only a segment straddling a chunk boundary is
/// copied — roughly one per upstream read, not one per MSS segment. Callers
/// guarantee `start < end <= sum(chunk lengths)`.
fn slice_chunks(chunks: &[Bytes], start: usize, end: usize) -> Bytes {
    let mut pos = 0;
    let mut idx = 0;
    // Advance to the chunk containing `start` (`pos` = its start offset).
    while pos + chunks[idx].len() <= start {
        pos += chunks[idx].len();
        idx += 1;
    }
    let local_start = start - pos;
    if end <= pos + chunks[idx].len() {
        return chunks[idx].slice(local_start..end - pos);
    }
    // The range straddles a chunk boundary: copy it out contiguous.
    let mut buffer = BytesMut::with_capacity(end - start);
    buffer.extend_from_slice(&chunks[idx][local_start..]);
    pos += chunks[idx].len();
    idx += 1;
    while pos < end {
        let chunk = &chunks[idx];
        let take = (end - pos).min(chunk.len());
        buffer.extend_from_slice(&chunk[..take]);
        pos += chunk.len();
        idx += 1;
    }
    buffer.freeze()
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
    // A FIN is only queued when the unacked queue is empty (guarded above), so
    // the pipe was 0 / earliest None: this lone segment (length 1 for the FIN
    // flag) becomes the whole pipe.
    let sent_at = Instant::now();
    state.unacked_server_segments.push_back(ServerSegment {
        sequence_number,
        acknowledgement_number: state.rcv_nxt,
        flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
        payload: Bytes::new(),
        last_sent: sent_at,
        first_sent: sent_at,
        retransmits: 0,
        rto_retransmits: 0,
        fast_retransmit_epoch: 0,
        delivered_snapshot: state.bbr.delivered,
        delivered_at_snapshot: state.bbr.delivered_at,
        first_tx_snapshot: state.first_tx_mstamp,
        app_limited: true,
    });
    state.pipe_bytes += 1;
    state.pipe_segments += 1;
    state.earliest_unsacked_sent.get_or_insert(sent_at);
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
