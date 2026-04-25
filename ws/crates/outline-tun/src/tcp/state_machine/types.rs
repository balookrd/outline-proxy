use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, watch};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

use outline_transport::{SocketTcpWriter, VlessTcpWriter, WsTcpWriter};
#[cfg(feature = "quic")]
use outline_transport::QuicTcpWriter;
use crate::TunRoute;
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

pub(in crate::tcp) struct TcpFlowState {
    pub(in crate::tcp) id: u64,
    pub(in crate::tcp) key: TcpFlowKey,
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
    pub(in crate::tcp) receive_window_capacity: usize,
    pub(in crate::tcp) smoothed_rtt: Option<Duration>,
    pub(in crate::tcp) rttvar: Duration,
    pub(in crate::tcp) retransmission_timeout: Duration,
    pub(in crate::tcp) congestion_window: usize,
    pub(in crate::tcp) slow_start_threshold: usize,
    pub(in crate::tcp) pending_server_data: VecDeque<Bytes>,
    pub(in crate::tcp) backlog_limit_exceeded_since: Option<Instant>,
    pub(in crate::tcp) last_ack_progress_at: Instant,
    pub(in crate::tcp) pending_client_data: VecDeque<Bytes>,
    pub(in crate::tcp) unacked_server_segments: VecDeque<ServerSegment>,
    pub(in crate::tcp) sack_scoreboard: Vec<SequenceRange>,
    pub(in crate::tcp) pending_client_segments: VecDeque<BufferedClientSegment>,
    pub(in crate::tcp) server_fin_pending: bool,
    pub(in crate::tcp) zero_window_probe_backoff: Duration,
    pub(in crate::tcp) next_zero_window_probe_at: Option<Instant>,
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
    pub(in crate::tcp) retransmits: u32,
}

#[derive(Debug, Default)]
pub(in crate::tcp) struct ServerFlush {
    pub(in crate::tcp) data_packets: Vec<Vec<u8>>,
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

#[derive(Debug, Clone, Copy)]
pub(in crate::tcp) struct AckEffect {
    pub(in crate::tcp) bytes_acked: usize,
    pub(in crate::tcp) rtt_sample: Option<Duration>,
    pub(in crate::tcp) grow_congestion_window: bool,
    pub(in crate::tcp) retransmit_now: bool,
}

impl AckEffect {
    pub(in crate::tcp) const fn none() -> Self {
        Self {
            bytes_acked: 0,
            rtt_sample: None,
            grow_congestion_window: false,
            retransmit_now: false,
        }
    }

    pub(in crate::tcp) const fn has_ack_progress(self) -> bool {
        self.bytes_acked != 0 || self.rtt_sample.is_some()
    }
}
