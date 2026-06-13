//! Shared Shadowsocks (AEAD) primitives reused by the WebSocket and raw-QUIC
//! SS carriers: the TCP-session handshake (per-key trial decrypt + target
//! parse) and the UDP datagram decrypt / NAT-relay path. The standalone
//! `ss_listen` plain TCP+UDP listeners that used to live alongside these were
//! removed (trivially DPI-detectable, no clients of this deployment used
//! them); only the primitives the wrapped transports share survive here.

mod handshake;
mod udp;

pub(in crate::server) use handshake::ss_tcp_handshake;
pub(in crate::server) use udp::{SsUdpClientId, SsUdpCtx, handle_ss_udp_packet};
