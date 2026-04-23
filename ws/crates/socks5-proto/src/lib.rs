//! SOCKS5 protocol primitives: request parsing, UDP fragment reassembly,
//! authentication negotiation, and the shared [`TargetAddr`] / auth-config
//! types. Extracted into a standalone crate for isolated testing and reuse.

mod config;
mod constants;
mod error;
mod handshake;
mod reassembly;
mod target;
mod udp;

pub use config::{Socks5AuthConfig, Socks5AuthUserConfig};
pub use constants::{
    SOCKS5_UDP_FRAGMENT_END, SOCKS5_UDP_FRAGMENT_MASK, SOCKS5_UDP_REASSEMBLY_MAX_BYTES,
    SOCKS5_UDP_REASSEMBLY_TIMEOUT, SOCKS_METHOD_NO_ACCEPTABLE, SOCKS_METHOD_NO_AUTH,
    SOCKS_METHOD_USERNAME_PASSWORD, SOCKS_CMD_CONNECT, SOCKS_CMD_UDP_ASSOCIATE,
    SOCKS_CMD_UDP_IN_TCP, SOCKS_REP_ADDRESS_NOT_SUPPORTED, SOCKS_REP_COMMAND_NOT_SUPPORTED,
    SOCKS_REP_NOT_ALLOWED, SOCKS_REP_SUCCESS, SOCKS_VERSION,
};
pub use error::{Result, Socks5Error};
pub use handshake::{SocksRequest, negotiate, send_reply};
pub use reassembly::{ReassembledUdpPacket, UdpFragmentReassembler};
pub use target::{
    SOCKS_ATYP_DOMAIN, SOCKS_ATYP_IPV4, SOCKS_ATYP_IPV6, TargetAddr, socket_addr_to_target,
};
pub use udp::{
    Socks5UdpPacket, Socks5UdpTcpPacket, build_udp_packet, parse_udp_request, read_udp_tcp_packet,
    write_udp_tcp_packet,
};
