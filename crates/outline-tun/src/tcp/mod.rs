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
pub(crate) use self::state_machine::UpstreamWriter;
#[cfg(test)]
pub(crate) use self::wire::parse_tcp_packet as parse_tcp_packet_for_tests;
#[cfg(test)]
use self::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN, build_reset_response, parse_tcp_packet};
use self::wire::{ParsedTcpPacket, build_response_packet_custom};

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
    advertised_receive_window, retransmit_budget_exhausted, retransmit_due_segment,
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
const TCP_FAST_RETRANSMIT_DUP_ACKS: u8 = 3;
const MAX_SERVER_SEGMENT_PAYLOAD: usize = 1200;
const TCP_SERVER_RECV_WINDOW_CAPACITY: usize = 262_144;
const TCP_SERVER_WINDOW_SCALE: u8 = 2;
const TCP_INITIAL_RTO: Duration = Duration::from_secs(1);
const TCP_MIN_RTO: Duration = Duration::from_millis(200);
const TCP_MAX_RTO: Duration = Duration::from_secs(60);
const TCP_INITIAL_CWND_SEGMENTS: usize = 10;
const TCP_MIN_SSTHRESH: usize = MAX_SERVER_SEGMENT_PAYLOAD * 2;

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
const BBR_CWND_GAIN: f64 = 2.0;
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
/// Token-bucket burst ceiling for the pacer, as a multiple of MSS: large
/// enough that ACK-clocked refills are never the bottleneck, small enough that
/// the instantaneous burst stays well under a typical port buffer.
const BBR_PACING_MAX_BURST_SEGMENTS: usize = 64;
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct TcpFlowKey {
    version: IpVersion,
    client_ip: IpAddr,
    client_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}
