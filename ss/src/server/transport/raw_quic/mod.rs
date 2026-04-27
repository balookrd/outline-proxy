//! Raw VLESS / Shadowsocks framed directly over QUIC streams.
//!
//! Distinct from the WebSocket-over-HTTP/3 path: there is no HTTP/3 framing
//! and no Extended CONNECT. ALPN selects the protocol on the same QUIC
//! endpoint, then each bidi stream carries one VLESS request or one SS TCP
//! session.

mod oversize;
mod ss;
mod vless;

pub(in crate::server) use oversize::{
    OversizeStream, OversizeStreamSlot, StreamKind, classify_accept_bi,
};
pub(in crate::server) use ss::{
    RawQuicSsCtx, SsQuicConn, handle_raw_ss_quic_stream_with_prefix,
    serve_raw_ss_oversize_records, serve_raw_ss_quic_datagrams,
};
pub(in crate::server) use vless::{
    RawQuicVlessRouteCtx, VlessQuicConn, handle_raw_vless_quic_stream_with_prefix,
    serve_raw_vless_oversize_records, serve_raw_vless_quic_datagrams,
};
