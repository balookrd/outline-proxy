use std::net::IpAddr;
use std::time::Duration;

use crate::wire::IpVersion;

#[cfg(test)]
pub(crate) mod engine;
#[cfg(not(test))]
mod engine;
mod maintenance;
mod state_machine;
mod validation;
mod wire;

#[cfg(test)]
mod tests;

pub use self::engine::TunTcpEngine;
#[cfg(test)]
pub(crate) use self::state_machine::{UpstreamCarrier, UpstreamWriter};
#[cfg(test)]
pub(crate) use self::wire::parse_tcp_packet_unverified as parse_tcp_packet_for_tests;
#[cfg(test)]
use self::wire::{
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, build_reset_response, parse_tcp_packet_unverified,
};
use self::wire::{
    ParsedTcpPacket, build_data_header_custom, build_gso_tcp_header, build_response_packet_custom,
};

#[cfg(test)]
use self::state_machine::{
    BbrState, BufferedClientSegment, ClientSegmentView, QueueFutureSegmentOutcome, ServerSegment,
    TcpFlowState, TcpFlowStatus, TrimmedSegment, assess_server_backlog_pressure,
    build_flow_ack_packet, build_flow_syn_ack_packet, drain_ready_buffered_segments,
    exceeds_client_reassembly_limits, is_duplicate_syn, maybe_emit_zero_window_probe,
    normalize_client_segment, note_ack_progress, note_congestion_event, process_server_ack,
    queue_future_segment, queue_future_segment_with_recv_window, reset_zero_window_persist,
    retransmit_oldest_unacked_packet, update_client_send_window,
};

#[cfg(test)]
use self::state_machine::{
    advertised_receive_window, rebuild_unacked_accounting, retransmit_budget_exhausted,
    retransmit_due_segment, server_segment_is_sacked, server_segment_len,
};
#[cfg(test)]
use outline_transport::UpstreamTransportGuard;

pub(crate) const TCP_FLAG_FIN: u8 = 0x01;
pub(crate) const TCP_FLAG_SYN: u8 = 0x02;
pub(crate) const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_PSH: u8 = 0x08;
pub(crate) const TCP_FLAG_ACK: u8 = 0x10;
const TCP_ZERO_WINDOW_PROBE_BASE_INTERVAL: Duration = Duration::from_secs(1);
const TCP_ZERO_WINDOW_PROBE_MAX_INTERVAL: Duration = Duration::from_secs(30);
/// Delayed-ACK hold time: a lone in-order data segment defers its standalone
/// ACK this long instead of eliciting one immediately, so a steady uplink ACKs
/// roughly every 2nd segment (RFC 5681 §4.2) — halving pure-ACK TUN writes on
/// the single read-loop, which is what caps uplink throughput when the kernel
/// does not coalesce inbound segments (no GRO on the forward-to-TUN path). Kept
/// far below `TCP_MIN_RTO` (200 ms) so it never trips the client's RTO, and
/// short because the client terminates ~0 RTT away, so any ACK delay adds
/// directly to its perceived RTT and would otherwise throttle its send window.
const TCP_DELAYED_ACK_TIMEOUT: Duration = Duration::from_millis(5);
const TCP_FAST_RETRANSMIT_DUP_ACKS: u8 = 3;
const MAX_SERVER_SEGMENT_PAYLOAD: usize = 1200;
/// Max payload coalesced into one downlink TSO super-segment (`[tun] gso`). The
/// kernel splits it into MSS segments; kept well under 65535 − headers so the
/// IPv4 `total_len` / IPv6 `payload_len` u16 fields never overflow.
const GSO_MAX_SUPER_SEGMENT_PAYLOAD: usize = 61_440;
/// Window-scale shift advertised to the client in the SYN-ACK. It must be large
/// enough that the full `max_buffered_client_bytes` uplink window is
/// representable on the wire: the advertised value is `available >> shift`
/// clamped to `u16::MAX`, so the ceiling is `65535 << shift`. At shift 6 that is
/// ~4 MiB, covering the config cap. A smaller shift (was 2 → 256 KiB ceiling)
/// silently pinned the uplink receive window — and thus uplink throughput — far
/// below a fast last-mile BDP, even after the buffer itself was enlarged.
const TCP_SERVER_WINDOW_SCALE: u8 = 6;
const TCP_INITIAL_RTO: Duration = Duration::from_secs(1);
const TCP_MIN_RTO: Duration = Duration::from_millis(200);
const TCP_MAX_RTO: Duration = Duration::from_secs(60);
/// Ceiling for the *exponential backoff* of the RTO on repeated timeout
/// retransmits of the same hole. The generic `TCP_MAX_RTO` (60 s) is meant for
/// dead-path detection, but this stack terminates the client locally and proxies
/// media: on a lossy last mile a retransmit can itself be dropped, and letting
/// the backoff balloon to multiple seconds freezes video for that long. Capping
/// the backoff keeps a lost retransmit's re-send prompt (≤ this) so recovery is
/// seconds, not tens of seconds. It does NOT change the dead-flow abort, which
/// keys off the retransmit *count* (`retransmit_budget_exhausted`), not timing;
/// a genuinely dead path is still reaped by that budget and the keepalive/idle
/// timers. Only the backoff on `note_congestion_event` uses this; the RTT
/// estimator still clamps to `TCP_MAX_RTO` (never reached on a sub-ms hop).
const TCP_MAX_RTO_BACKOFF: Duration = Duration::from_secs(2);
const TCP_INITIAL_CWND_SEGMENTS: usize = 10;

// --- BBR-style downlink pacing / in-flight control -------------------------
//
// The userspace stack terminates TCP ~1 ms from the client, so the legacy
// Reno window inflates to the client's (huge) receive window within a couple
// of milliseconds and the flush dumps a whole segment at line rate. On a
// 100 Mbit last hop that burst overruns the router's port buffer and collapses
// the flow. BBR fixes this by pacing at the *measured* bottleneck bandwidth and
// capping in-flight at the bandwidth-delay product, so the stack never offers
// the path more than it can drain. See `state_machine/bbr.rs`.
//
/// Pacing+cwnd gain while ramping in STARTUP (2/ln2): doubles the send rate
/// each round until the measured bandwidth stops growing.
const BBR_STARTUP_GAIN: f64 = 2.885;
/// Pacing gain in DRAIN — the reciprocal of the STARTUP gain, sized to drain
/// in one round the standing queue STARTUP built up.
const BBR_DRAIN_GAIN: f64 = 0.346;
/// Steady-state head-room over the BDP for the in-flight cap. 2×BDP keeps the
/// pipe full across delayed/stretch ACKs without overrunning the buffer.
///
/// It is *not* the answer to a path whose RTT exceeds its min-RTT by more than
/// this factor — see `BBR_EXTRA_ACKED_WIN_ROUNDS`. Raising it would trade one
/// hard-coded ratio for another and hand every path a queue sized for the worst
/// one; canonical BBR measures the shortfall instead.
const BBR_CWND_GAIN: f64 = 2.0;
/// Rounds a slot of the ACK-aggregation estimate stays open — canonical BBR's
/// `bbr_extra_acked_win_rtts`. Two slots are kept and the max taken over both,
/// so the estimate spans 5-10 round trips: long enough to remember an aggregate
/// that only arrives every few rounds, short enough to forget a path that has
/// stopped bursting.
///
/// This is the head-room the in-flight cap needs on top of `gain × BDP`, and it
/// exists because the cap is computed from `min_rtt` while the flight it bounds
/// comes back over the path's *actual* RTT. Where `srtt / min_rtt` exceeds
/// `BBR_CWND_GAIN` a cap-bound flight delivers less than the estimate it was
/// derived from, and the two ratchet each other down: the field gateway measured
/// `srtt / min_rtt = 2.73` against a gain of 2.0 and pinned a mac on Wi-Fi at
/// 3 MB/s of a link carrying 33.
///
/// The excess RTT *is* the aggregation — a packet waits for the radio's TXOP,
/// then a whole aggregate lands at once — so the bytes the path holds back are
/// exactly what `extra_acked` measures, and adding them back sizes the pipe for
/// the silence between aggregates. Measured, not assumed: a path that does not
/// burst yields 0 and gets the canonical `gain × BDP` cap, which is what keeps
/// this from handing a small last-hop buffer a queue it cannot hold (`194fa962`).
const BBR_EXTRA_ACKED_WIN_ROUNDS: u32 = 5;
/// Ceiling on the aggregation head-room, expressed as a duration of bandwidth —
/// canonical BBR's `bbr_extra_acked_max_us`. Bounds what an under-estimated
/// BtlBw can talk the cap into while the two are still converging: until the
/// estimate catches up, deliveries outrun it every epoch and the raw excess has
/// no upper bound of its own.
const BBR_EXTRA_ACKED_MAX_WINDOW: Duration = Duration::from_millis(100);
/// PROBE_BW pacing-gain cycle (one entry per min-RTT phase): probe up, drain
/// the probe, then cruise. Lets the estimate track a bottleneck that changes.
const BBR_PROBE_BW_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// Floor on the in-flight cap so a tiny BDP (sub-ms RTT) still admits enough
/// packets to keep ACKs flowing and avoid stop-and-go.
const BBR_MIN_PIPE_CWND_SEGMENTS: usize = 4;
/// Horizon (in round-trips) of the windowed-max filter that tracks BtlBw, so a
/// transient dip in delivery rate does not shrink the estimate.
const BBR_BW_WINDOW_ROUNDS: u64 = 10;
/// Horizon for the windowed-min RTT estimate; after it expires the next sample
/// reseeds min-RTT (and PROBE_RTT forces a fresh measurement).
const BBR_MIN_RTT_WINDOW: Duration = Duration::from_secs(10);
/// How long to hold the pipe near-empty in PROBE_RTT to observe a clean RTT.
const BBR_PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// In-flight cap (in segments) held during PROBE_RTT.
const BBR_PROBE_RTT_CWND_SEGMENTS: usize = 4;
/// STARTUP is "full" once BtlBw fails to grow by this factor for
/// `BBR_STARTUP_FULL_BW_COUNT` consecutive rounds.
const BBR_STARTUP_GROWTH_TARGET: f64 = 1.25;
const BBR_STARTUP_FULL_BW_COUNT: u32 = 3;
/// Floor on the pacer's token-bucket burst ceiling, as a multiple of MSS.
///
/// It binds below ~4.8 MB/s, and it is what keeps the rate-proportional budget
/// from strangling a slow path on our clock. Canonical BBR floors the same
/// quantity at 2 segments (`bbr_min_tso_segs`), which is safe only because its
/// hrtimer fires again microseconds later; at our 0.5–4 ms flush gap a 2-segment
/// bucket ceilings delivery at `2 × MSS / gap` ≈ 1.6–3 MB/s, which would throttle
/// exactly the slow last hop this controller exists to protect.
const BBR_PACING_MAX_BURST_SEGMENTS: usize = 16;
/// How much of the pacer's own clock jitter the burst ceiling must cover.
///
/// The bucket only sustains `pacing_rate` if a flush arrives at least every
/// `cap / rate`; refill accrued past `cap` is discarded, and the discarded time
/// never comes back. So the ceiling is a *duration*, not a packet count: it has
/// to span the gap between consecutive flushes, or the pacer systematically
/// under-delivers.
///
/// A fixed `16 × MSS` was a duration that shrank as the path got faster — 19 KB
/// is 6 ms at 3 MB/s but only 0.64 ms at 30 MB/s. Measured on the deployment,
/// flushes actually arrive every 0.5–4.4 ms (ACK aggregation on the radio hop,
/// plus the maintenance timer's ~1 ms granularity backing the pacing wakeup), so
/// at 30 MB/s the cap threw away 50–88% of the refill and held a 22–36 MB/s
/// pacing rate down to 9–16 MB/s of actual delivery.
///
/// Canonical BBR sizes the same quantity off the rate, not the MSS
/// (`tcp_small_queue_check` / `tcp_tso_autosize` → `sk_pacing_rate >>
/// sk_pacing_shift` ≈ 1 ms of data — the same form as [`tso_segs_goal`]), and
/// can afford 1 ms because an hrtimer re-enters the transmit path within
/// microseconds of the earliest departure time. Our clock is coarser, so we
/// budget for its measured jitter instead of the kernel's.
///
/// Copying the kernel's 1 ms verbatim was measured, not assumed: sizing the cap
/// straight off `tso_segs_goal` delivered 12.2 MB/s against this constant's
/// 24.3 MB/s (7 interleaved runs each; the worst 4 ms run beat the best 1 ms
/// run). 1 ms of credit simply expires before a flush that lands 2–4 ms later
/// can spend it, so the kernel's constant only works on the kernel's clock.
const BBR_PACING_BURST_CLOCK_JITTER: Duration = Duration::from_millis(4);
/// Absolute ceiling on the pacer's burst, however fast the path is measured to
/// be. This is a sanity bound, not the working limit: what actually holds the
/// burst down is the send window (`min(reno_cwnd, bbr_inflight_cap)`), which the
/// flush checks independently, and the rate-proportional budget above — a slow
/// client's burst stays small because its own measured rate is small.
const BBR_PACING_MAX_BURST_BYTES: u64 = 262_144;
/// Multiplicative back-off applied to the loss-driven bandwidth cap on a round
/// whose measured loss rate exceeded `BBR_LOSS_THRESH` (0.85 ≈ −15%). Never
/// applied without the `bw_latest` floor in `adapt_loss_cap` — the back-off
/// proposes, the floor disposes.
const BBR_LOSS_CAP_BACKOFF: f64 = 0.85;
/// Loss rate (lost / (lost + delivered), measured over a round) above which the
/// last hop is treated as congested and the cap backs off. Canonical BBRv2's
/// `bbr_loss_thresh` — 5/256 ≈ 1.953% in the kernel's fixed point, 2% here.
///
/// Below this the loss is the medium's, not a queue's: a radio link drops
/// sporadically at rates orders of magnitude under this, and reacting to it
/// throttles a healthy flow. This is the gate the old per-episode back-off
/// lacked — it counted *events*, so one dropped segment (3 dup-ACKs → recovery
/// entry) cost 15% of the cap regardless of whether 30 or 30_000 segments had
/// gone out around it.
const BBR_LOSS_THRESH: f64 = 0.02;
/// Minimum bytes (lost + delivered) a loss-rate measurement window must hold
/// before its ratio is trusted; short of it the counters carry into the next
/// round instead of being evaluated.
///
/// A round on a sub-ms hop can be a couple of dozen segments, where a single
/// drop reads as 3-6% and would clear `BBR_LOSS_THRESH` on noise alone. At
/// ~100 segments one drop is ~1% (below the threshold) and two are ~2% (at it),
/// which is the resolution the threshold implies. Canonical BBRv2 needs no such
/// floor because it divides by `tx_in_flight` — the in-flight snapshot taken
/// when the ACKed packet was *sent* — which we do not track per segment.
const BBR_LOSS_MIN_SAMPLE_BYTES: u64 = 100 * MAX_SERVER_SEGMENT_PAYLOAD as u64;
/// Floor for the loss-driven cap (bytes/sec) so a pathological path cannot
/// collapse the pacer to a standstill; ≈1 Mbit/s, below which the last hop is
/// unusable for media anyway. Secondary to the `bw_latest` floor, which is what
/// normally stops the cap descending below what the link demonstrably carries.
const BBR_LOSS_CAP_FLOOR_BPS: u64 = 125_000;
const TCP_TIME_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Fail-fast window for direct connects. A destination that failed to connect
/// within this window is not re-dialed with a fresh (up to `connect_timeout`,
/// default 10 s) attempt — the flow is reset immediately. This stops an
/// unreachable origin the client keeps re-dialing (e.g. a censored host such as
/// a blocked Telegram DC) from parking a connect task per attempt: a reconnect
/// storm to a blackhole otherwise piles up hundreds of 10 s dials and collapses
/// the engine (observed: 12.5k pkt/s, stack SYN-ACK latency 1 ms → 187 ms).
const TCP_CONNECT_FAILURE_TTL: Duration = Duration::from_secs(4);
/// Upper bound on the negative-connect-cache size (bounded resource; expired
/// entries are swept when the cap is hit).
const TCP_CONNECT_FAILURE_CACHE_CAP: usize = 4096;
/// Interval for the watchdog GC loop that sweeps the TCP flow table for
/// entries whose per-flow maintenance task died without removing the flow.
/// The per-flow maintenance task is the primary idle-cleanup path; this
/// loop is a safety net against task panics / spurious exits.
const TUN_TCP_FLOW_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
/// Granularity of the flow eviction (LRU) index. `last_seen` advances on every
/// accepted packet and every downlink chunk, but re-indexing costs a `BTreeSet`
/// remove + insert behind the engine-wide eviction mutex, so a flow is only
/// re-indexed once its `last_seen` has advanced by at least this much. Chosen
/// orders of magnitude below the idle timeout that decides which flows are
/// genuinely stale, so the coarser order still ranks a flow taking traffic above
/// one that has gone quiet. See `engine::eviction::eviction_index_needs_refresh`.
const TCP_EVICTION_INDEX_QUANTUM: Duration = Duration::from_secs(1);
/// How long a flow must have been quiet before the GC tick reclaims the capacity
/// its per-flow queues grew to during a transfer. Well above the ACK cadence of
/// a live transfer, so an active flow is never shrunk only to regrow on the next
/// chunk. See `state_machine::reclaim_flow_queue_capacity`.
const TCP_QUEUE_RECLAIM_IDLE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct TcpFlowKey {
    version: IpVersion,
    client_ip: IpAddr,
    client_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}
