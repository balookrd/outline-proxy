use std::net::IpAddr;
use std::time::Duration;

use crate::tun_wire::IpVersion;

mod engine;
mod maintenance;
mod state_machine;
mod validation;
mod wire;

#[cfg(test)]
mod tests;

pub use self::engine::TunTcpEngine;
#[cfg(test)]
pub(crate) use self::wire::parse_tcp_packet as parse_tcp_packet_for_tests;
#[cfg(test)]
use self::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN, build_reset_response, parse_tcp_packet};
use self::wire::{ParsedTcpPacket, build_response_packet_custom};

#[cfg(test)]
use self::state_machine::{
    BufferedClientSegment, ClientSegmentView, ServerSegment, TcpFlowState, TcpFlowStatus,
    assess_server_backlog_pressure, build_flow_ack_packet, build_flow_syn_ack_packet,
    drain_ready_buffered_segments, exceeds_client_reassembly_limits, is_duplicate_syn,
    maybe_emit_zero_window_probe, normalize_client_segment, note_ack_progress,
    note_congestion_event, process_server_ack, queue_future_segment, reset_zero_window_persist,
    retransmit_oldest_unacked_packet, update_client_send_window,
};

#[cfg(test)]
use crate::transport::UpstreamTransportGuard;

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
const TCP_TIME_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    version: IpVersion,
    client_ip: IpAddr,
    client_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}
