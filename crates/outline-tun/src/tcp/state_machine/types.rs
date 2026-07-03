use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, Notify, watch};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

use crate::TunRoute;
use crate::vnet::VirtioNetHdr;
#[cfg(feature = "quic")]
use outline_transport::QuicTcpWriter;
use outline_transport::{SocketTcpWriter, VlessTcpWriter, WsTcpWriter};
use outline_uplink::UplinkManager;

use super::super::TcpFlowKey;
use super::super::engine::scheduler::FlowScheduler;

/// Abstraction over the upstream TCP write half — tunneled (Shadowsocks
/// framing) or direct (plain bytes).
///
/// `TunneledWs` and `TunneledSocket` are kept as separate variants so that
/// each arm of `send_chunk` / `close` dispatches directly into a
/// monomorphized, branch-free implementation rather than going through a
/// second runtime check inside the writer.
pub enum UpstreamWriter {
    TunneledWs(WsTcpWriter),
    TunneledSocket(SocketTcpWriter),
    TunneledVless(VlessTcpWriter),
    #[cfg(feature = "quic")]
    TunneledQuicSs(QuicTcpWriter),
    Direct(OwnedWriteHalf),
}

impl UpstreamWriter {
    pub(in crate::tcp) async fn send_chunk(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::TunneledWs(w) => w.send_chunk(data).await,
            Self::TunneledSocket(w) => w.send_chunk(data).await,
            Self::TunneledVless(w) => w.send_chunk(data).await,
            #[cfg(feature = "quic")]
            Self::TunneledQuicSs(w) => w.send_chunk(data).await,
            Self::Direct(w) => w.write_all(data).await.context("direct TCP write failed"),
        }
    }

    pub(in crate::tcp) async fn close(&mut self) -> Result<()> {
        match self {
            Self::TunneledWs(w) => w.close().await,
            Self::TunneledSocket(w) => w.close().await,
            Self::TunneledVless(w) => w.close().await,
            #[cfg(feature = "quic")]
            Self::TunneledQuicSs(w) => w.close().await,
            Self::Direct(w) => w.shutdown().await.context("direct TCP shutdown failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tcp) enum TcpFlowStatus {
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

/// Routing/binding data for a flow — which group and uplink it lives on,
/// how to reach the upstream, and which route (tunneled vs direct) it was
/// opened for. Fixed after flow creation except `upstream_writer` /
/// `uplink_index` / `uplink_name`, which are updated on runtime failover.
pub(in crate::tcp) struct FlowRouting {
    pub(in crate::tcp) uplink_index: usize,
    pub(in crate::tcp) uplink_name: Arc<str>,
    pub(in crate::tcp) group_name: Arc<str>,
    /// The group's manager this flow is bound to. All per-flow operations
    /// (strict-active checks, connect, runtime failover) go through this
    /// manager, not the engine's default group.
    pub(in crate::tcp) manager: UplinkManager,
    /// The route this flow was created for — `Group` for tunneled flows,
    /// `Direct` for local-socket direct route.
    pub(in crate::tcp) route: TunRoute,
    pub(in crate::tcp) upstream_writer: Option<Arc<Mutex<UpstreamWriter>>>,
}

/// External notification channels a flow exposes — the close broadcaster
/// used by per-flow tasks to observe abort, and the shared deadline
/// scheduler that drives the central maintenance loop.
///
/// `idle_timeout` is carried here because it is per-flow policy; the shared
/// `TunTcpConfig` is owned by the engine and passed in explicitly to
/// maintenance calls to avoid an Arc per flow.
pub(in crate::tcp) struct FlowControlSignals {
    pub(in crate::tcp) close_signal: watch::Sender<bool>,
    /// Wakes the per-flow upstream pump task after the read-loop appends
    /// client payload to `pending_client_data` (or marks a half-close).
    /// The pump is the sole writer to `upstream_writer` after connect, so
    /// the read-loop hands work off through the buffer + this notify and
    /// never blocks on upstream backpressure itself.
    pub(in crate::tcp) upstream_pump: Arc<Notify>,
    /// Wakes the per-flow upstream *reader* after the client ACKs and
    /// `flush_server_output` drains `pending_server_data` below the soft
    /// limit. The reader pauses draining the carrier while the downlink
    /// buffer is over the limit (downlink backpressure), so a slow client
    /// cannot grow the buffer into the hard-limit RST that used to tear down
    /// healthy large downloads; this notify releases the reader once the
    /// client has made room.
    pub(in crate::tcp) server_drain: Arc<Notify>,
    pub(in crate::tcp) scheduler: Arc<FlowScheduler>,
    pub(in crate::tcp) idle_timeout: Duration,
}

/// Wall-clock markers: creation, last status transition, last observed
/// traffic. Read by the maintenance loop to compute deadlines; written on
/// state transitions and packet ingress.
#[derive(Debug, Clone, Copy)]
pub(in crate::tcp) struct FlowTimestamps {
    pub(in crate::tcp) created_at: Instant,
    pub(in crate::tcp) status_since: Instant,
    pub(in crate::tcp) last_seen: Instant,
}

/// BBR operating mode. Drives the pacing/cwnd gains and the in-flight cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tcp) enum BbrMode {
    /// Exponential ramp to discover the bottleneck bandwidth.
    Startup,
    /// Drain the standing queue STARTUP created, down to the BDP.
    Drain,
    /// Steady state: cruise at BtlBw, periodically probe up/down for changes.
    ProbeBw,
    /// Hold the pipe near-empty briefly to observe an unqueued min-RTT.
    ProbeRtt,
}

/// One entry in the BtlBw windowed-max filter: a delivery-rate sample tagged
/// with the round it was taken in, so samples older than the window age out.
#[derive(Debug, Clone, Copy)]
pub(in crate::tcp) struct BwSample {
    pub(in crate::tcp) bytes_per_sec: u64,
    pub(in crate::tcp) round: u64,
}

/// Per-flow BBR state. Estimates bottleneck bandwidth (windowed-max of the
/// per-packet delivery rate) and min-RTT (windowed-min), then derives the
/// pacing rate (`gain × BtlBw`) and in-flight cap (`cwnd_gain × BtlBw ×
/// min_rtt`). The pacer is a token bucket refilled on each ACK-clocked flush,
/// so timer granularity is not the throughput ceiling.
#[derive(Debug, Clone)]
pub(in crate::tcp) struct BbrState {
    /// Cumulative client-acknowledged bytes (the BBR "delivered" counter).
    pub(in crate::tcp) delivered: u64,
    /// Wall-clock of the last `delivered` update — the time anchor for the
    /// next rate sample.
    pub(in crate::tcp) delivered_at: Instant,
    /// Windowed-max filter over the last `BBR_BW_WINDOW_ROUNDS` rounds.
    pub(in crate::tcp) bw_filter: [BwSample; 3],
    /// Current BtlBw estimate in bytes/sec (max of the filter). 0 until the
    /// first delivery-rate sample arrives.
    pub(in crate::tcp) btlbw_bps: u64,
    /// Round-trip counter; a round elapses when an ACK covers a segment sent
    /// at or after the start of the current round.
    pub(in crate::tcp) round_count: u64,
    /// `delivered` snapshot marking the end of the current round.
    pub(in crate::tcp) next_round_delivered: u64,
    /// BtlBw at the start of the current STARTUP plateau check.
    pub(in crate::tcp) full_bw: u64,
    /// Consecutive rounds BtlBw failed to grow by `BBR_STARTUP_GROWTH_TARGET`.
    pub(in crate::tcp) full_bw_count: u32,
    /// Windowed-min RTT estimate; the basis for the BDP.
    pub(in crate::tcp) min_rtt: Duration,
    /// Wall-clock when `min_rtt` was last (re)seeded.
    pub(in crate::tcp) min_rtt_stamp: Instant,
    pub(in crate::tcp) mode: BbrMode,
    pub(in crate::tcp) pacing_gain: f64,
    pub(in crate::tcp) cwnd_gain: f64,
    /// Index into `BBR_PROBE_BW_GAINS` for the current PROBE_BW phase.
    pub(in crate::tcp) probe_bw_phase: usize,
    /// Wall-clock when the current PROBE_BW phase began.
    pub(in crate::tcp) cycle_stamp: Instant,
    /// When set, the instant PROBE_RTT may end (pipe held empty until then).
    pub(in crate::tcp) probe_rtt_done_at: Option<Instant>,
    /// Token-bucket pacing credit in bytes.
    pub(in crate::tcp) pacing_credit: u64,
    /// Wall-clock of the last pacing-credit refill.
    pub(in crate::tcp) pacing_refilled_at: Instant,
    /// When the pacer stopped a flush with data still queued: the instant a
    /// maintenance wakeup should resume it (timer fallback when ACKs stop).
    pub(in crate::tcp) pacing_next_at: Option<Instant>,
    /// Hard ceiling on the effective bandwidth (bytes/sec) used for pacing and
    /// the in-flight cap; caps the STARTUP overshoot so a line-rate burst does
    /// not overrun a small last-hop buffer. `0` disables the cap.
    pub(in crate::tcp) max_rate_bps: u64,
    /// Loss-driven soft ceiling on the effective bandwidth (bytes/sec), `0` when
    /// inactive. Plain BBR keys BtlBw off the windowed-max delivery rate and
    /// ignores loss, so on a sub-ms hop it locks onto the *peak burst* rate and
    /// keeps pacing at line rate straight into a lossy last mile. This cap backs
    /// off multiplicatively on each loss episode and relaxes back toward BtlBw on
    /// loss-free rounds (AIMD), so the pacer converges on the rate the last hop
    /// actually drains without dropping — recovering full speed once loss stops.
    pub(in crate::tcp) loss_cap_bps: u64,
    /// Whether a loss episode was recorded in the current BBR round; gates the
    /// per-round relaxation of `loss_cap_bps` so the cap only grows on a clean
    /// round.
    pub(in crate::tcp) loss_in_round: bool,
}

impl BbrState {
    /// Fresh BBR state for a new flow: STARTUP, no bandwidth/RTT samples yet,
    /// pacing inactive (the small initial cwnd bounds the first burst until the
    /// first sample arrives). `max_rate_bps` is the configured downlink ceiling
    /// (0 = uncapped).
    pub(in crate::tcp) fn new(now: Instant, max_rate_bps: u64) -> Self {
        Self {
            delivered: 0,
            delivered_at: now,
            bw_filter: [BwSample { bytes_per_sec: 0, round: 0 }; 3],
            btlbw_bps: 0,
            round_count: 0,
            next_round_delivered: 0,
            full_bw: 0,
            full_bw_count: 0,
            min_rtt: Duration::ZERO,
            min_rtt_stamp: now,
            mode: BbrMode::Startup,
            pacing_gain: super::super::BBR_STARTUP_GAIN,
            cwnd_gain: super::super::BBR_STARTUP_GAIN,
            probe_bw_phase: 0,
            cycle_stamp: now,
            probe_rtt_done_at: None,
            pacing_credit: 0,
            pacing_refilled_at: now,
            pacing_next_at: None,
            max_rate_bps,
            loss_cap_bps: 0,
            loss_in_round: false,
        }
    }
}

pub(in crate::tcp) struct TcpFlowState {
    pub(in crate::tcp) id: u64,
    pub(in crate::tcp) key: TcpFlowKey,
    /// Whether the TUN fd negotiated TSO offload (`TunOffloadCaps::tso`). When
    /// true, `flush_server_data` may coalesce the downlink into one super-segment
    /// the kernel splits per MSS instead of building N per-MSS packets. Segment
    /// tracking (`unacked_server_segments`) stays per-MSS regardless.
    pub(in crate::tcp) gso_enabled: bool,
    pub(in crate::tcp) routing: FlowRouting,
    pub(in crate::tcp) signals: FlowControlSignals,
    pub(in crate::tcp) status: TcpFlowStatus,
    pub(in crate::tcp) rcv_nxt: u32,
    pub(in crate::tcp) client_window_scale: u8,
    pub(in crate::tcp) client_sack_permitted: bool,
    pub(in crate::tcp) client_max_segment_size: Option<u16>,
    pub(in crate::tcp) timestamps_enabled: bool,
    pub(in crate::tcp) recent_client_timestamp: Option<u32>,
    pub(in crate::tcp) server_timestamp_offset: u32,
    pub(in crate::tcp) client_window: u32,
    pub(in crate::tcp) client_window_end: u32,
    pub(in crate::tcp) client_window_update_seq: u32,
    pub(in crate::tcp) client_window_update_ack: u32,
    pub(in crate::tcp) server_seq: u32,
    pub(in crate::tcp) last_client_ack: u32,
    pub(in crate::tcp) duplicate_ack_count: u8,
    pub(in crate::tcp) fast_recovery_end: Option<u32>,
    /// Monotonic counter bumped on each entry into fast recovery. A segment's
    /// `fast_retransmit_epoch` is matched against this to tell "already
    /// fast-retransmitted in the current episode" apart from "first sent
    /// during this episode", so each hole is resent at most once per episode.
    pub(in crate::tcp) recovery_epoch: u64,
    pub(in crate::tcp) receive_window_capacity: usize,
    pub(in crate::tcp) smoothed_rtt: Option<Duration>,
    pub(in crate::tcp) rttvar: Duration,
    pub(in crate::tcp) retransmission_timeout: Duration,
    pub(in crate::tcp) congestion_window: usize,
    pub(in crate::tcp) slow_start_threshold: usize,
    /// BBR-style downlink rate/in-flight controller. Paces the server→client
    /// send at the measured bottleneck bandwidth and caps in-flight at the BDP,
    /// so the stack never bursts more onto the last hop than it can drain.
    pub(in crate::tcp) bbr: BbrState,
    pub(in crate::tcp) pending_server_data: VecDeque<Bytes>,
    /// Running byte total of `pending_server_data`, kept in sync at the push /
    /// split-to sites so `pending_server_bytes` is O(1) instead of summing the
    /// whole deque on every downlink chunk and metric commit. A `debug_assert`
    /// in `pending_server_bytes` cross-checks it against the live sum in tests.
    pub(in crate::tcp) pending_server_bytes_total: usize,
    pub(in crate::tcp) backlog_limit_exceeded_since: Option<Instant>,
    pub(in crate::tcp) last_ack_progress_at: Instant,
    pub(in crate::tcp) pending_client_data: VecDeque<Bytes>,
    pub(in crate::tcp) unacked_server_segments: VecDeque<ServerSegment>,
    pub(in crate::tcp) sack_scoreboard: Vec<SequenceRange>,
    pub(in crate::tcp) pending_client_segments: VecDeque<BufferedClientSegment>,
    pub(in crate::tcp) server_fin_pending: bool,
    pub(in crate::tcp) zero_window_probe_backoff: Duration,
    pub(in crate::tcp) next_zero_window_probe_at: Option<Instant>,
    /// Delayed-ACK: count of in-order data segments accepted since we last sent
    /// an ACK for the current `rcv_nxt`. A steady stream ACKs on the 2nd (RFC
    /// 5681), so this only ever holds 0 or 1; a lone segment arms
    /// `delayed_ack_deadline` instead of eliciting an immediate pure-ACK,
    /// halving ACK writes on the read-loop.
    pub(in crate::tcp) unacked_in_order_segments: u8,
    /// When set, a delayed ACK is owed and the maintenance loop must emit it by
    /// this instant. Cleared whenever any ACK covering the current `rcv_nxt` is
    /// sent (immediate ACK, piggybacked downlink data, or the timer firing).
    pub(in crate::tcp) delayed_ack_deadline: Option<Instant>,
    pub(in crate::tcp) keepalive_probes_sent: u32,
    pub(in crate::tcp) last_keepalive_probe_at: Option<Instant>,
    /// Last-emitted values for Prometheus gauges. Private to the metric
    /// sync code (`sync_flow_metrics` / `clear_flow_metrics`); used to
    /// compute +/- deltas so the gauge accumulates correctly.
    pub(in crate::tcp) reported: ReportedFlowMetrics,
    pub(in crate::tcp) timestamps: FlowTimestamps,
    /// Most recently scheduled maintenance deadline for this flow.  A heap
    /// entry in `FlowScheduler` is considered live only when its deadline
    /// matches this value; any other popped entry is a stale leftover from
    /// a previous `sync_flow_metrics_and_schedule` call and is dropped.
    pub(in crate::tcp) next_scheduled_deadline: Option<Instant>,
}

/// Cache of last values emitted to Prometheus gauges for this flow.
/// Separated from the protocol fields in `TcpFlowState` so metric
/// bookkeeping (`sync_flow_metrics` / `clear_flow_metrics`) does not
/// visually mix with TCP state.
#[derive(Debug, Default)]
pub(in crate::tcp) struct ReportedFlowMetrics {
    pub(in crate::tcp) inflight_segments: usize,
    pub(in crate::tcp) inflight_bytes: usize,
    pub(in crate::tcp) pending_server_bytes: usize,
    pub(in crate::tcp) buffered_client_segments: usize,
    pub(in crate::tcp) zero_window: bool,
    pub(in crate::tcp) backlog_pressure: bool,
    pub(in crate::tcp) backlog_pressure_us: u64,
    pub(in crate::tcp) ack_progress_stall: bool,
    pub(in crate::tcp) ack_progress_stall_us: u64,
    pub(in crate::tcp) active: bool,
    pub(in crate::tcp) congestion_window: usize,
    pub(in crate::tcp) slow_start_threshold: usize,
    pub(in crate::tcp) retransmission_timeout_us: u64,
    pub(in crate::tcp) smoothed_rtt_us: u64,
}

#[derive(Debug)]
pub(in crate::tcp) struct ClientSegmentView {
    pub(in crate::tcp) payload: Bytes,
    pub(in crate::tcp) fin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tcp) struct BufferedClientSegment {
    pub(in crate::tcp) sequence_number: u32,
    pub(in crate::tcp) flags: u8,
    pub(in crate::tcp) payload: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tcp) struct SequenceRange {
    pub(in crate::tcp) start: u32,
    pub(in crate::tcp) end: u32,
}

#[derive(Debug, Clone)]
pub(in crate::tcp) struct ServerSegment {
    pub(in crate::tcp) sequence_number: u32,
    pub(in crate::tcp) acknowledgement_number: u32,
    pub(in crate::tcp) flags: u8,
    pub(in crate::tcp) payload: Bytes,
    pub(in crate::tcp) last_sent: Instant,
    pub(in crate::tcp) first_sent: Instant,
    /// Total times this segment was put back on the wire (fast-retransmit
    /// *and* RTO). Used by Karn's algorithm to suppress RTT samples from
    /// retransmitted segments — NOT a death signal.
    pub(in crate::tcp) retransmits: u32,
    /// RTO-driven retransmits only. This is the genuine dead-path signal:
    /// the budget abort (`retransmit_budget_exhausted`) keys off this, so a
    /// burst of SACK-driven fast-retransmits cannot falsely reap a live flow.
    pub(in crate::tcp) rto_retransmits: u32,
    /// `recovery_epoch` in which this segment was last fast-retransmitted, or
    /// 0 if never. Compared against the flow's current `recovery_epoch` so a
    /// hole is fast-retransmitted at most once per recovery episode (RFC 6675
    /// behaviour) instead of once per incoming partial SACK.
    pub(in crate::tcp) fast_retransmit_epoch: u64,
    /// Value of `bbr.delivered` at the moment this segment was first sent. On
    /// ACK, `(bbr.delivered_now - delivered_snapshot) / (now - first_sent)` is
    /// the BBR delivery-rate sample for this segment.
    pub(in crate::tcp) delivered_snapshot: u64,
    /// Whether the flow was application-limited (downlink buffer drained, not
    /// bandwidth-limited) when this segment was sent. Such a sample only raises
    /// the BtlBw estimate, never lowers it — an idle gap is not a slow path.
    pub(in crate::tcp) app_limited: bool,
}

/// One downlink packet to write to the TUN device.
#[derive(Debug)]
pub(in crate::tcp) struct ServerDataPacket {
    pub(in crate::tcp) bytes: Vec<u8>,
    /// `Some` when `bytes` is a TSO super-segment: the `virtio_net_hdr` the
    /// writer prepends so the kernel splits it into `gso_size` MSS segments.
    /// `None` is a single IP packet (writer emits a GSO_NONE header or a bare
    /// write, depending on whether the fd carries a vnet header).
    pub(in crate::tcp) vnet: Option<VirtioNetHdr>,
}

impl ServerDataPacket {
    pub(in crate::tcp) fn single(bytes: Vec<u8>) -> Self {
        Self { bytes, vnet: None }
    }
}

#[derive(Debug, Default)]
pub(in crate::tcp) struct ServerFlush {
    pub(in crate::tcp) data_packets: Vec<ServerDataPacket>,
    pub(in crate::tcp) fin_packet: Option<Vec<u8>>,
    pub(in crate::tcp) probe_packet: Option<Vec<u8>>,
    pub(in crate::tcp) window_stalled: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(in crate::tcp) struct ServerBacklogPressure {
    pub(in crate::tcp) exceeded: bool,
    pub(in crate::tcp) should_abort: bool,
    pub(in crate::tcp) pending_bytes: usize,
    pub(in crate::tcp) over_limit_ms: Option<u128>,
    pub(in crate::tcp) no_progress_ms: Option<u128>,
    pub(in crate::tcp) window_stalled: bool,
}

/// BBR delivery-rate sample, taken from the oldest cleanly-acked segment of an
/// ACK (retransmitted segments are skipped, like RTT samples under Karn's
/// algorithm). The rate is `(delivered_now - prior_delivered) / (now -
/// sent_at)`.
#[derive(Debug, Clone, Copy)]
pub(in crate::tcp) struct RateSample {
    pub(in crate::tcp) prior_delivered: u64,
    pub(in crate::tcp) sent_at: Instant,
    pub(in crate::tcp) app_limited: bool,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::tcp) struct AckEffect {
    pub(in crate::tcp) bytes_acked: usize,
    pub(in crate::tcp) rtt_sample: Option<Duration>,
    pub(in crate::tcp) grow_congestion_window: bool,
    pub(in crate::tcp) retransmit_now: bool,
    pub(in crate::tcp) rate_sample: Option<RateSample>,
}

impl AckEffect {
    pub(in crate::tcp) const fn none() -> Self {
        Self {
            bytes_acked: 0,
            rtt_sample: None,
            grow_congestion_window: false,
            retransmit_now: false,
            rate_sample: None,
        }
    }

    pub(in crate::tcp) const fn has_ack_progress(self) -> bool {
        self.bytes_acked != 0 || self.rtt_sample.is_some()
    }
}
