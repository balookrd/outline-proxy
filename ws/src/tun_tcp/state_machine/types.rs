use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{Mutex, Notify, watch};

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

use crate::transport::TcpShadowsocksWriter;
use crate::tun::TunRoute;
use crate::uplink::UplinkManager;

use super::super::TcpFlowKey;

/// Abstraction over the upstream TCP write half — tunneled (Shadowsocks
/// framing) or direct (plain bytes).
pub enum TunTcpUpstreamWriter {
    Tunneled(TcpShadowsocksWriter),
    Direct(OwnedWriteHalf),
}

impl TunTcpUpstreamWriter {
    pub(in crate::tun_tcp) async fn send_chunk(&mut self, data: &[u8]) -> Result<()> {
        match self {
            Self::Tunneled(w) => w.send_chunk(data).await,
            Self::Direct(w) => w.write_all(data).await.context("direct TCP write failed"),
        }
    }

    pub(in crate::tun_tcp) async fn close(&mut self) -> Result<()> {
        match self {
            Self::Tunneled(w) => w.close().await,
            Self::Direct(w) => w.shutdown().await.context("direct TCP shutdown failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tun_tcp) enum TcpFlowStatus {
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

pub(in crate::tun_tcp) struct TcpFlowState {
    pub(in crate::tun_tcp) id: u64,
    pub(in crate::tun_tcp) key: TcpFlowKey,
    pub(in crate::tun_tcp) uplink_index: usize,
    pub(in crate::tun_tcp) uplink_name: String,
    /// The group's manager this flow is bound to. All per-flow operations
    /// (strict-active checks, connect, runtime failover) go through this
    /// manager, not the engine's default group.
    pub(in crate::tun_tcp) manager: UplinkManager,
    /// The route this flow was created for — `Group` for tunneled flows,
    /// `Direct` for local-socket direct route.
    pub(in crate::tun_tcp) route: TunRoute,
    pub(in crate::tun_tcp) upstream_writer: Option<Arc<Mutex<TunTcpUpstreamWriter>>>,
    pub(in crate::tun_tcp) close_signal: watch::Sender<bool>,
    pub(in crate::tun_tcp) maintenance_notify: Arc<Notify>,
    pub(in crate::tun_tcp) status: TcpFlowStatus,
    pub(in crate::tun_tcp) client_next_seq: u32,
    pub(in crate::tun_tcp) client_window_scale: u8,
    pub(in crate::tun_tcp) client_sack_permitted: bool,
    pub(in crate::tun_tcp) client_max_segment_size: Option<u16>,
    pub(in crate::tun_tcp) timestamps_enabled: bool,
    pub(in crate::tun_tcp) recent_client_timestamp: Option<u32>,
    pub(in crate::tun_tcp) server_timestamp_offset: u32,
    pub(in crate::tun_tcp) client_window: u32,
    pub(in crate::tun_tcp) client_window_end: u32,
    pub(in crate::tun_tcp) client_window_update_seq: u32,
    pub(in crate::tun_tcp) client_window_update_ack: u32,
    pub(in crate::tun_tcp) server_seq: u32,
    pub(in crate::tun_tcp) last_client_ack: u32,
    pub(in crate::tun_tcp) duplicate_ack_count: u8,
    pub(in crate::tun_tcp) fast_recovery_end: Option<u32>,
    pub(in crate::tun_tcp) receive_window_capacity: usize,
    pub(in crate::tun_tcp) smoothed_rtt: Option<Duration>,
    pub(in crate::tun_tcp) rttvar: Duration,
    pub(in crate::tun_tcp) retransmission_timeout: Duration,
    pub(in crate::tun_tcp) congestion_window: usize,
    pub(in crate::tun_tcp) slow_start_threshold: usize,
    pub(in crate::tun_tcp) pending_server_data: VecDeque<Bytes>,
    pub(in crate::tun_tcp) backlog_limit_exceeded_since: Option<Instant>,
    pub(in crate::tun_tcp) last_ack_progress_at: Instant,
    pub(in crate::tun_tcp) pending_client_data: VecDeque<Bytes>,
    pub(in crate::tun_tcp) unacked_server_segments: VecDeque<ServerSegment>,
    pub(in crate::tun_tcp) sack_scoreboard: Vec<SequenceRange>,
    pub(in crate::tun_tcp) pending_client_segments: VecDeque<BufferedClientSegment>,
    pub(in crate::tun_tcp) server_fin_pending: bool,
    pub(in crate::tun_tcp) zero_window_probe_backoff: Duration,
    pub(in crate::tun_tcp) next_zero_window_probe_at: Option<Instant>,
    /// Last-emitted values for Prometheus gauges. Private to the metric
    /// sync code (`sync_flow_metrics` / `clear_flow_metrics`); used to
    /// compute +/- deltas so the gauge accumulates correctly.
    pub(in crate::tun_tcp) reported: ReportedFlowMetrics,
    pub(in crate::tun_tcp) created_at: Instant,
    pub(in crate::tun_tcp) status_since: Instant,
    pub(in crate::tun_tcp) last_seen: Instant,
}

/// Cache of last values emitted to Prometheus gauges for this flow. Kept
/// out of the main TCP state so readers of `TcpFlowState` see only
/// protocol-relevant fields, not metric bookkeeping.
#[derive(Debug, Default)]
pub(in crate::tun_tcp) struct ReportedFlowMetrics {
    pub(in crate::tun_tcp) inflight_segments: usize,
    pub(in crate::tun_tcp) inflight_bytes: usize,
    pub(in crate::tun_tcp) pending_server_bytes: usize,
    pub(in crate::tun_tcp) buffered_client_segments: usize,
    pub(in crate::tun_tcp) zero_window: bool,
    pub(in crate::tun_tcp) backlog_pressure: bool,
    pub(in crate::tun_tcp) backlog_pressure_us: u64,
    pub(in crate::tun_tcp) ack_progress_stall: bool,
    pub(in crate::tun_tcp) ack_progress_stall_us: u64,
    pub(in crate::tun_tcp) active: bool,
    pub(in crate::tun_tcp) congestion_window: usize,
    pub(in crate::tun_tcp) slow_start_threshold: usize,
    pub(in crate::tun_tcp) retransmission_timeout_us: u64,
    pub(in crate::tun_tcp) smoothed_rtt_us: u64,
}

#[derive(Debug)]
pub(in crate::tun_tcp) struct ClientSegmentView {
    pub(in crate::tun_tcp) payload: Bytes,
    pub(in crate::tun_tcp) fin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tun_tcp) struct BufferedClientSegment {
    pub(in crate::tun_tcp) sequence_number: u32,
    pub(in crate::tun_tcp) flags: u8,
    pub(in crate::tun_tcp) payload: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tun_tcp) struct SequenceRange {
    pub(in crate::tun_tcp) start: u32,
    pub(in crate::tun_tcp) end: u32,
}

#[derive(Debug, Clone)]
pub(in crate::tun_tcp) struct ServerSegment {
    pub(in crate::tun_tcp) sequence_number: u32,
    pub(in crate::tun_tcp) acknowledgement_number: u32,
    pub(in crate::tun_tcp) flags: u8,
    pub(in crate::tun_tcp) payload: Bytes,
    pub(in crate::tun_tcp) last_sent: Instant,
    pub(in crate::tun_tcp) first_sent: Instant,
    pub(in crate::tun_tcp) retransmits: u32,
}

#[derive(Debug, Default)]
pub(in crate::tun_tcp) struct ServerFlush {
    pub(in crate::tun_tcp) data_packets: Vec<Vec<u8>>,
    pub(in crate::tun_tcp) fin_packet: Option<Vec<u8>>,
    pub(in crate::tun_tcp) probe_packet: Option<Vec<u8>>,
    pub(in crate::tun_tcp) window_stalled: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(in crate::tun_tcp) struct ServerBacklogPressure {
    pub(in crate::tun_tcp) exceeded: bool,
    pub(in crate::tun_tcp) should_abort: bool,
    pub(in crate::tun_tcp) pending_bytes: usize,
    pub(in crate::tun_tcp) over_limit_ms: Option<u128>,
    pub(in crate::tun_tcp) no_progress_ms: Option<u128>,
    pub(in crate::tun_tcp) window_stalled: bool,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::tun_tcp) struct AckEffect {
    pub(in crate::tun_tcp) bytes_acked: usize,
    pub(in crate::tun_tcp) rtt_sample: Option<Duration>,
    pub(in crate::tun_tcp) grow_congestion_window: bool,
    pub(in crate::tun_tcp) retransmit_now: bool,
}

impl AckEffect {
    pub(in crate::tun_tcp) const fn none() -> Self {
        Self {
            bytes_acked: 0,
            rtt_sample: None,
            grow_congestion_window: false,
            retransmit_now: false,
        }
    }

    pub(in crate::tun_tcp) const fn has_ack_progress(self) -> bool {
        self.bytes_acked != 0 || self.rtt_sample.is_some()
    }
}
