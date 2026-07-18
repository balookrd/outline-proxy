use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, Notify, watch};

use anyhow::{Context, Result};
use socks5_proto::TargetAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

use crate::TunRoute;
use crate::utils::{maybe_shrink_vec, maybe_shrink_vecdeque};
use crate::vnet::VirtioNetHdr;
use outline_transport::{SocketTcpWriter, VlessTcpWriter, WsTcpWriter};
use outline_uplink::UplinkManager;

use super::super::TcpFlowKey;
use super::super::engine::scheduler::FlowScheduler;
use super::resume::FlowResume;

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
    Direct(OwnedWriteHalf),
}

impl UpstreamWriter {
    pub(in crate::tcp) async fn send_chunk(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::TunneledWs(w) => w.send_chunk(data).await,
            Self::TunneledSocket(w) => w.send_chunk(data).await,
            Self::TunneledVless(w) => w.send_chunk(data).await,
            Self::Direct(w) => w.write_all(data).await.context("direct TCP write failed"),
        }
    }

    /// Vectored [`Self::send_chunk`]: ships a batch of client payload chunks upstream without
    /// the pump first concatenating them into one contiguous buffer. Each tunneled writer feeds
    /// the chunks straight into its framer with a bounded scratch/frame, dropping the
    /// full-window allocation + memcpy the uplink hot path used to pay per iteration.
    pub(in crate::tcp) async fn send_chunks(&mut self, chunks: &[Bytes]) -> Result<()> {
        match self {
            Self::TunneledWs(w) => w.send_chunks(chunks).await,
            Self::TunneledSocket(w) => w.send_chunks(chunks).await,
            Self::TunneledVless(w) => w.send_chunks(chunks).await,
            Self::Direct(w) => {
                for chunk in chunks {
                    w.write_all(chunk).await.context("direct TCP write failed")?;
                }
                Ok(())
            },
        }
    }

    pub(in crate::tcp) async fn close(&mut self) -> Result<()> {
        match self {
            Self::TunneledWs(w) => w.close().await,
            Self::TunneledSocket(w) => w.close().await,
            Self::TunneledVless(w) => w.close().await,
            Self::Direct(w) => w.shutdown().await.context("direct TCP shutdown failed"),
        }
    }
}

/// The flow's upstream write half, plus the epoch of the carrier it belongs to.
///
/// The two travel together behind one mutex on purpose. A carrier migration
/// replaces `writer` in place (the pump keeps writing to the same `Arc` and does
/// not need respawning) and stamps the new `epoch` in the same critical section;
/// the pump, which sampled the epoch when it took its batch out of the flow's
/// buffer and mirrored it into the replay ring, compares the two before it
/// writes. Equal means "this is still the carrier I accounted that batch
/// against" — send it. Different means a migration has since replayed the ring,
/// batch included, onto a fresh carrier — so the pump must drop the batch rather
/// than put those bytes on the wire a second time.
///
/// Bundling them is what makes that check atomic: an epoch kept anywhere else
/// could change between the pump's read of it and its write to the writer.
pub struct UpstreamCarrier {
    pub(in crate::tcp) writer: UpstreamWriter,
    /// `0` for the carrier the flow connected on; incremented by each committed
    /// migration. Mirrors `FlowResume::carrier_epoch`, which is the copy the
    /// pump reads under the *flow* lock.
    pub(in crate::tcp) epoch: u64,
}

impl UpstreamCarrier {
    /// The carrier a flow connects on: epoch `0`, no migration behind it.
    pub(in crate::tcp) fn new(writer: UpstreamWriter) -> Self {
        Self { writer, epoch: 0 }
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
/// opened for. Fixed after flow creation except `upstream_carrier` /
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
    /// The destination this flow dialled: the literal IP the client addressed,
    /// or the domain connection sniffing recovered from its first bytes. Held so
    /// a carrier migration re-dials the same destination the flow established
    /// on. (On a resume *hit* the server ignores the handshake target and
    /// re-attaches the parked upstream — but the handshake still carries one,
    /// and the honest value is the one this flow actually used.)
    pub(in crate::tcp) target: TargetAddr,
    pub(in crate::tcp) upstream_carrier: Option<Arc<Mutex<UpstreamCarrier>>>,
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
    /// The pump is the sole writer to `upstream_carrier` after connect, so
    /// the read-loop hands work off through the buffer + this notify and
    /// never blocks on upstream backpressure itself.
    pub(in crate::tcp) upstream_pump: Arc<Notify>,
    /// Wakes the pump when a carrier migration reaches a verdict — committed
    /// (the pump resumes on the fresh carrier) or abandoned (the pump falls back
    /// to the teardown it would have done anyway). A pump that fails a send on a
    /// dead carrier parks on this rather than resetting the flow out from under
    /// a migration that is about to save it. Notified with `notify_one`, so a
    /// verdict reached before the pump parks is kept as a permit and the wakeup
    /// is never lost.
    pub(in crate::tcp) carrier_migration: Arc<Notify>,
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
    /// inactive — canonical BBRv2's `bw_lo` (`BBR.bw_shortterm` in the ccwg
    /// draft). Bounds the pacing rate and the BDP alike, so a last hop that
    /// cannot drain what BtlBw claims still gets paced at what it does drain.
    ///
    /// Maintained once per round by `bbr::adapt_loss_cap`, never per loss
    /// episode: the back-off is gated on a *measured* loss rate over the round
    /// and floored at `bw_latest_bps`, so it can only ever pull the flow down to
    /// what the link actually delivered — never below it.
    pub(in crate::tcp) loss_cap_bps: u64,
    /// Whether a loss episode was recorded in the current BBR round. Cuts a
    /// PROBE_BW gain phase short (a path with small buffers may not hold
    /// `gain × BDP` at all); the cap itself keys off `lost_in_window`, not this.
    pub(in crate::tcp) loss_in_round: bool,
    /// Highest delivery-rate sample (bytes/sec) seen in the current loss-rate
    /// measurement window — canonical BBRv2's `bw_latest`, but on the window's
    /// clock rather than the round's, so it answers "what did this link carry
    /// over the same bytes the loss rate was read from", not "ever".
    ///
    /// The window is what makes it a floor. Measured per *round* — as the canon
    /// does, where a round is also the loss-measurement interval — it read
    /// 463 KB/s on a link the same flow was pulling 3.5 MB/s through, because our
    /// window spans several rounds and a single short round's best sample is not
    /// representative of them. `× 0.85` then won the `max()` and the clamp below
    /// never bound.
    ///
    /// This is the floor under every loss back-off, and the reason a lossy but
    /// uncongested path is no longer throttled: on a link delivering 9 MB/s,
    /// `max(bw_latest, cap × 0.85)` cannot resolve below 9 MB/s, so sporadic
    /// radio loss cannot bite. On a path whose last hop is genuinely overrun the
    /// deliveries themselves fall, `bw_latest` falls with them, and the cap
    /// follows it down. Canonical BBRv2 (`bbr2_adapt_lower_bounds`): "we do not
    /// cut our short-term estimates lower than the current rate and volume of
    /// delivered data from this round trip".
    pub(in crate::tcp) bw_latest_bps: u64,
    /// Bytes retransmitted — the stack's proxy for bytes lost — in the current
    /// loss-rate measurement window. Numerator of the `BBR_LOSS_THRESH` ratio.
    pub(in crate::tcp) lost_in_window: u64,
    /// Bytes delivered in the current loss-rate measurement window. The window
    /// spans whole rounds and only closes once it holds
    /// `BBR_LOSS_MIN_SAMPLE_BYTES`, so the ratio is never taken off a handful of
    /// segments.
    pub(in crate::tcp) delivered_in_window: u64,
    /// Monotonic count of loss episodes seen by this flow (each `note_loss`
    /// call: fast-recovery entry or RTO). Never decreases, so the metrics sync
    /// can export it as a Prometheus counter by delta — telling "the loss cap is
    /// parked at the floor because loss keeps arriving" apart from "the cap is
    /// stuck low although loss stopped".
    pub(in crate::tcp) loss_episodes: u64,
    /// Windowed max (bytes) of how much more was ACKed over a stretch than
    /// BtlBw predicted for it — canonical BBR's `extra_acked[2]`. Two slots, the
    /// current one retired every `BBR_EXTRA_ACKED_WIN_ROUNDS` rounds, so the max
    /// over both spans 5-10 round trips.
    ///
    /// This is the burstiness the path itself introduces (Wi-Fi aggregation,
    /// stretch ACKs), and `bbr::ack_aggregation_cwnd` adds it to the in-flight
    /// cap so the pipe stays busy across the silence between aggregates instead
    /// of being throttled by a bound derived from `min_rtt`.
    pub(in crate::tcp) extra_acked: [u64; 2],
    /// Which slot of `extra_acked` is currently accumulating.
    pub(in crate::tcp) extra_acked_win_idx: usize,
    /// Rounds since the current `extra_acked` slot was opened.
    pub(in crate::tcp) extra_acked_win_rounds: u32,
    /// Start of the current ACK-aggregation sampling epoch — canonical BBR's
    /// `ack_epoch_mstamp`. An epoch spans a stretch that ran *ahead* of BtlBw;
    /// it restarts the moment deliveries fall back to what BtlBw predicts, which
    /// is why an inter-ACK silence does not itself read as aggregation.
    pub(in crate::tcp) ack_epoch_stamp: Instant,
    /// Bytes ACKed since `ack_epoch_stamp` — canonical BBR's `ack_epoch_acked`.
    pub(in crate::tcp) ack_epoch_acked: u64,
    /// Long-term in-flight ceiling (bytes) — canonical BBRv2's `inflight_hi`.
    /// The largest in-flight a probe carried *without* provoking loss over
    /// `BBR_LOSS_THRESH`; pinned down to the in-flight at which loss appeared,
    /// lifted back up by a clean PROBE_BW gain-up phase. `usize::MAX` until the
    /// first congestion signal, so before that the BDP cap alone bounds the
    /// flight. Replaces the Reno congestion window as the upper in-flight bound.
    pub(in crate::tcp) inflight_hi: usize,
    /// Short-term in-flight ceiling (bytes) — canonical BBRv2's `inflight_lo`.
    /// Backed off `× BBR_CWND_LOSS_BETA` from the flight when loss crosses the
    /// threshold and reset to `usize::MAX` when a gain-up phase begins (canonical
    /// `bbr2_reset_lower_bounds`), so it snaps back to `inflight_hi` fast instead
    /// of crawling up on a Reno additive increase. This is the reaction that
    /// replaces the Reno `/2` (later `× 0.85`) window cut on every loss.
    pub(in crate::tcp) inflight_lo: usize,
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
            loss_episodes: 0,
            bw_latest_bps: 0,
            lost_in_window: 0,
            delivered_in_window: 0,
            extra_acked: [0; 2],
            extra_acked_win_idx: 0,
            extra_acked_win_rounds: 0,
            ack_epoch_stamp: now,
            ack_epoch_acked: 0,
            inflight_hi: usize::MAX,
            inflight_lo: usize::MAX,
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
    /// What a carrier migration needs to re-attach this flow's server-parked
    /// upstream on a fresh carrier: the flow's own Session ID, the uplink replay
    /// ring, the downstream-accepted byte offset, and the bookkeeping that keeps
    /// the reader (which migrates) and the pump (which must not fight it) in
    /// step. Armed on a successful tunneled connect (see
    /// `tasks/upstream/connect.rs`); stays [`FlowResume::disarmed`] on a direct
    /// flow, which has no carrier to migrate off.
    pub(in crate::tcp) resume: FlowResume,
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
    /// Recovery point (`server_seq`/snd_nxt at the instant of the last cwnd
    /// reduction) that gates *re*-reduction. A burst that drops a run of
    /// segments is one congestion event; without this, recovery exits the moment
    /// the first hole is repaired and immediately re-enters for the next hole in
    /// the same burst, compounding `× BBR_CWND_LOSS_BETA` once per RTT into a
    /// ~×0.2 collapse (measured: 10 cuts in 67 ms, cwnd 375→73 KB). Reduction is
    /// suppressed while `last_client_ack` has not yet passed this point — i.e.
    /// while the flight in progress at the first cut is still draining — so a
    /// single burst reduces the window exactly once. Cleared naturally by the
    /// `seq_lt` comparison once the cumulative ACK passes it.
    pub(in crate::tcp) cwnd_reduction_recovery_point: Option<u32>,
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
    /// Running byte total of the un-SACKed segments in `unacked_server_segments`
    /// (`Σ server_segment_len` over segments not fully covered by the SACK
    /// scoreboard) — i.e. the in-flight "pipe". Maintained incrementally at the
    /// push / ACK / SACK / retransmit sites so `bytes_in_pipe` is O(1) instead
    /// of a full scan of the queue (each element itself an O(scoreboard) SACK
    /// probe) on every `congestion_window_remaining` call inside the flush loop.
    /// A `debug_assert` cross-checks it against the scan version on every read.
    pub(in crate::tcp) pipe_bytes: usize,
    /// Running count of the un-SACKed segments in `unacked_server_segments`
    /// (== `count_segments_in_pipe`). Maintained alongside [`Self::pipe_bytes`].
    pub(in crate::tcp) pipe_segments: usize,
    /// When the current flight started going out: set to the send instant
    /// whenever data is sent into an empty pipe. Snapshotted into each segment as
    /// `first_tx_snapshot`, and `first_sent - first_tx_snapshot` is that
    /// segment's send interval — the floor on the BBR rate interval. Canonical
    /// BBR's `tp->first_tx_mstamp` (`tcp_rate_skb_sent`).
    pub(in crate::tcp) first_tx_mstamp: Instant,
    /// Cached earliest `last_sent` among the un-SACKed segments, so
    /// `next_retransmission_deadline` is `earliest + rto` in O(1) instead of a
    /// min-scan of the queue on every `reschedule_flow`. `None` when nothing
    /// un-SACKed is in flight.
    pub(in crate::tcp) earliest_unsacked_sent: Option<Instant>,
    /// True when a retransmit rewrote a segment's `last_sent` out of position,
    /// so `last_sent` is no longer non-decreasing by queue position. On the
    /// loss-free (monotonic) path the earliest send instant is the first
    /// un-SACKed segment, refreshed in O(1) after an ACK; once set this forces
    /// the exact min-rescan instead. Self-clears once the reordered segment
    /// drains and order is restored.
    pub(in crate::tcp) unacked_reordered: bool,
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
    /// Pre-resolved per-`(group, uplink)` gauge handles for this flow, filled
    /// lazily on the first metric sync and re-resolved when the flow fails over
    /// to a different uplink. Kept next to (not inside) `reported` so the sync
    /// code can borrow the handles and the last-emitted deltas disjointly.
    pub(in crate::tcp) flow_gauges: Option<CachedFlowGauges>,
    pub(in crate::tcp) timestamps: FlowTimestamps,
    /// The `timestamps.last_seen` value currently reflected in the engine's
    /// `FlowEvictionIndex`. Kept next to the flow state so `record_flow_activity`
    /// can decide *without taking the engine-wide eviction lock* whether this
    /// packet advanced `last_seen` far enough (a whole `TCP_EVICTION_INDEX_QUANTUM`)
    /// to be worth re-indexing.
    pub(in crate::tcp) eviction_indexed_at: Instant,
    /// Most recently scheduled maintenance deadline for this flow.  A heap
    /// entry in `FlowScheduler` is considered live only when its deadline
    /// matches this value; any other popped entry is a stale leftover from
    /// a previous `sync_flow_metrics_and_schedule` call and is dropped.
    pub(in crate::tcp) next_scheduled_deadline: Option<Instant>,
}

/// Give back the capacity the per-flow queues grew to during a transfer.
///
/// The queues are sized by the transfer's BDP / window peak and are drained with
/// `pop_front` / `split_to`, which never returns the allocation — so a flow that
/// pulled one large download and then went quiet keeps holding it for as long as
/// it lives (a `ServerSegment` is ~96 B, so a few hundred in-flight segments are
/// tens of KB), multiplied by every live-but-idle flow.
///
/// Called from the GC tick for flows that have been quiet for
/// `TCP_QUEUE_RECLAIM_IDLE`, never from the packet path: shrinking a queue that
/// is about to refill just trades RSS for allocator churn. The `maybe_shrink_*`
/// helpers are additionally self-gating (they only act on a queue that is mostly
/// empty and above a floor capacity), so a repeat visit to an already-reclaimed
/// flow is a no-op.
///
/// Capacity only. Every running counter (`pipe_bytes`, `pipe_segments`,
/// `pending_server_bytes_total`, …) tracks queue *contents*, which this leaves
/// untouched.
pub(in crate::tcp) fn reclaim_flow_queue_capacity(state: &mut TcpFlowState) {
    maybe_shrink_vecdeque(&mut state.pending_server_data);
    maybe_shrink_vecdeque(&mut state.pending_client_data);
    maybe_shrink_vecdeque(&mut state.unacked_server_segments);
    maybe_shrink_vecdeque(&mut state.pending_client_segments);
    maybe_shrink_vec(&mut state.sack_scoreboard);
}

/// Cached gauge handles bound to the uplink they were resolved for. The
/// `sync_flow_metrics` hot path skips the 14 per-packet `with_label_values`
/// probes while the flow stays on `uplink`; a runtime failover swaps
/// `routing.uplink_name` to a fresh `Arc`, and the sync code re-resolves the
/// handles for the new uplink so emitted series match the per-call path
/// bit-for-bit.
pub(in crate::tcp) struct CachedFlowGauges {
    pub(in crate::tcp) uplink: Arc<str>,
    pub(in crate::tcp) handles: outline_metrics::TunTcpFlowGauges,
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
    pub(in crate::tcp) bbr_btlbw_bps: u64,
    pub(in crate::tcp) bbr_pacing_rate_bps: u64,
    pub(in crate::tcp) bbr_loss_cap_bps: u64,
    pub(in crate::tcp) bbr_inflight_hi_bytes: usize,
    pub(in crate::tcp) bbr_inflight_lo_bytes: usize,
    pub(in crate::tcp) bbr_loss_capped: bool,
    pub(in crate::tcp) bbr_min_rtt_us: u64,
    /// Last `BbrState::loss_episodes` value already added to the counter. Unlike
    /// every other field here this one is *not* unwound on close: the counter it
    /// feeds is monotonic, so `clear_flow_metrics` must leave both alone.
    pub(in crate::tcp) bbr_loss_episodes: u64,
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
    /// ACK, `(bbr.delivered_now - delivered_snapshot) / (now -
    /// delivered_at_snapshot)` is the BBR delivery-rate sample for this segment.
    pub(in crate::tcp) delivered_snapshot: u64,
    /// Value of `bbr.delivered_at` — the instant of the last ACK — at the moment
    /// this segment was first sent. Pairs with `delivered_snapshot`: it is the
    /// instant at which `delivered` held that value, so it is the correct start
    /// of the interval the sample divides by. See [`RateSample`].
    pub(in crate::tcp) delivered_at_snapshot: Instant,
    /// Value of `first_tx_mstamp` — the instant the current flight started going
    /// out — when this segment was first sent. `first_sent - first_tx_snapshot`
    /// is the flight's send interval, the floor on the rate interval.
    pub(in crate::tcp) first_tx_snapshot: Instant,
    /// Whether the flow was application-limited (downlink buffer drained, not
    /// bandwidth-limited) when this segment was sent. Such a sample only raises
    /// the BtlBw estimate, never lowers it — an idle gap is not a slow path.
    pub(in crate::tcp) app_limited: bool,
}

/// One downlink packet to write to the TUN device. The IP/TCP `header` and the
/// `payload` chunks are written vectored (`writev`) so the payload — which
/// already lives as owned `Bytes` upstream and on the retransmit scoreboard — is
/// never copied into a packet buffer. `payload` holds one chunk on the fast path
/// and several when a TSO super-segment coalesces multiple upstream reads
/// without copying them contiguous.
#[derive(Debug)]
pub(in crate::tcp) struct ServerDataPacket {
    pub(in crate::tcp) header: Vec<u8>,
    pub(in crate::tcp) payload: Vec<Bytes>,
    /// `Some` when this is a TSO super-segment: the `virtio_net_hdr` the writer
    /// prepends so the kernel splits `payload` into `gso_size` MSS segments and
    /// finalises each segment's L4 checksum. `None` is a single IP packet
    /// (writer emits a GSO_NONE header or a bare write, depending on whether the
    /// fd carries a vnet header).
    pub(in crate::tcp) vnet: Option<VirtioNetHdr>,
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
/// prior_mstamp)`.
///
/// Both ends of that fraction must be anchored to the *same* instant, which is
/// when `delivered` last equalled `prior_delivered` — not when the segment was
/// sent. Anchoring the denominator to the send instant divides every byte the
/// ACK released (including ones sent long before) by the short interval since
/// one recent segment left, inflating the estimate. Loss makes it worse: the
/// oldest segments become retransmits and get skipped, so the sample anchors to
/// an ever fresher segment. This is `prior_mstamp` in canonical BBR
/// (`tp->delivered_mstamp` snapshotted into each skb).
#[derive(Debug, Clone, Copy)]
pub(in crate::tcp) struct RateSample {
    pub(in crate::tcp) prior_delivered: u64,
    /// When `delivered` last equalled `prior_delivered`: the instant of the last
    /// ACK before this segment was sent.
    pub(in crate::tcp) prior_mstamp: Instant,
    /// How long this flight had been going out when this segment left: the
    /// segment's send instant minus the flight's first send instant. Bytes cannot
    /// have been *delivered* faster than we managed to *send* them, so the rate
    /// interval is `max(send_interval, ack_interval)` — without this floor, an
    /// ACK arriving a moment after the previous one divides a whole flight's
    /// worth of released bytes by a near-zero gap. That is the common case in
    /// loss recovery, where the sample skips the retransmitted (older) segments
    /// and lands on one sent mid-recovery. `interval_us` in `tcp_rate_gen`.
    pub(in crate::tcp) send_interval: Duration,
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
