//! Raw QUIC transport primitives.
//!
//! Three ALPNs match the outline-ss-rust server's per-protocol QUIC
//! listener: [`ALPN_VLESS`], [`ALPN_SS`], [`ALPN_H3`]. The server
//! registers them all on a single endpoint and dispatches by negotiated
//! ALPN; on the client side each ALPN gets its own connection (and its
//! own connection-cache registry, since two connections to the same
//! `host:port` differing only by ALPN are distinct).
//!
//! Wire formats per ALPN:
//!
//! * `vless` — bidi stream per session. Client writes the standard VLESS
//!   request header; server replies `[VERSION, 0x00]` for TCP or
//!   `[VERSION, 0x00, session_id_4B_BE]` for UDP. Multiple TCP / UDP
//!   sessions on the same connection. UDP datagrams are
//!   `session_id_4B_BE || payload`; demuxed at connection level by
//!   [`vless_udp::VlessUdpDemuxer`].
//!
//! * `ss` — bidi stream = one Shadowsocks AEAD TCP session (salt + target
//!   chunk + payload chunks). UDP datagrams = standard SS-AEAD UDP
//!   packets, one per datagram, target inside encrypted payload.
//!
//! * `h3` — handled by the existing `crate::h3` module (HTTP/3 with
//!   Extended CONNECT WebSocket).

#![cfg(feature = "quic")]

mod connection;
mod dial;
mod tls_config;
pub(crate) mod vless_udp;

pub use connection::SharedQuicConnection;
pub use dial::connect_quic_uplink;
pub(crate) use dial::gc_shared_quic_connections;

/// ALPN identifier for raw VLESS over QUIC.
pub const ALPN_VLESS: &[u8] = b"vless";
/// ALPN identifier for raw Shadowsocks over QUIC.
pub const ALPN_SS: &[u8] = b"ss";
/// ALPN identifier for HTTP/3 (used by the `crate::h3` module).
pub const ALPN_H3: &[u8] = b"h3";
