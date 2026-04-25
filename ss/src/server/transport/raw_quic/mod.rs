//! Raw VLESS / Shadowsocks framed directly over QUIC streams.
//!
//! Distinct from the WebSocket-over-HTTP/3 path: there is no HTTP/3 framing
//! and no Extended CONNECT. ALPN selects the protocol on the same QUIC
//! endpoint, then each bidi stream carries one VLESS request or one SS TCP
//! session.

mod ss;
mod vless;

pub(in crate::server) use ss::{
    RawQuicSsCtx, handle_raw_ss_quic_stream, serve_raw_ss_quic_datagrams,
};
pub(in crate::server) use vless::{
    RawQuicVlessRouteCtx, VlessQuicConn, handle_raw_vless_quic_stream,
    serve_raw_vless_quic_datagrams,
};
