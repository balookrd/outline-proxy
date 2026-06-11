//! VLESS client primitives (iteration 1: WS transport only, TCP + UDP,
//! no Mux, no flow/xtls).
//!
//! Wire format — request (client → server), emitted once on the first
//! WebSocket binary frame:
//!
//! ```text
//!   version(1) = 0x00
//!   uuid(16)
//!   addons_len(1) = 0x00
//!   command(1): TCP=0x01, UDP=0x02
//!   port(2 BE)
//!   atyp(1): 0x01=IPv4, 0x02=Domain(len+bytes), 0x03=IPv6
//!   addr(...)
//! ```
//!
//! For TCP the header may be immediately followed by the first chunk of
//! client payload in the same frame; subsequent frames carry raw bytes.
//!
//! For UDP the header is followed by `len(2 BE) || payload` repeated per
//! datagram; subsequent frames carry the same length-prefixed stream.
//!
//! Response (server → client) — first binary frame begins with
//! `[version=0x00, addons_len=0x00]`, followed by raw TCP bytes or the same
//! length-prefixed UDP stream.

mod header;
mod tcp;
mod udp;
mod udp_mux;
mod uuid;

pub use header::{
    build_vless_tcp_request_header, build_vless_tcp_request_header_with_resume,
    build_vless_udp_request_header,
};
pub use tcp::{VlessTcpReader, VlessTcpWriter, vless_tcp_pair_from_ws};
pub use udp::{VlessUdpTransport, VlessUdpWsTransport};
pub use udp_mux::{VlessUdpDowngradeNotifier, VlessUdpMuxLimits, VlessUdpSessionMux};
pub use uuid::parse_uuid;

#[cfg(test)]
#[path = "tests/vless.rs"]
mod tests;
