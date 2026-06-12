// Gate module for the locally patched vendored crates (`vendor/h3`,
// `vendor/sockudo-ws`) — client side.  Every API whose shape or behaviour
// exists only in the patched copies is reached through here, so a rebase of
// the vendored crates onto a new upstream starts at this file plus its
// server-side twin (`bins/outline-ss-rust/src/server/h3/vendored.rs`).  The
// patches themselves are documented in the root PATCHES.md.
//
// Patched surface funneled through this module:
//   - `h3::ext::Protocol::WEBSOCKET` — RFC 9220 Extended CONNECT value,
//     added by `h3-0.0.8.patch` (upstream 0.0.8 does not know it).
//   - `Stream::from_h3_client` + `WebSocketStream::from_raw` — the write
//     path of the resulting stream relies on the fix-h3-poll-write patch
//     pair (h3 `queue_send`/`poll_drain`/`queue_grease`/`poll_quic_finish`
//     driven by sockudo's `write_queued`/`shutdown_started` state machines).

use bytes::Bytes;
use h3::client::{RequestStream as H3RequestStream, SendRequest as H3SendRequest};
use sockudo_ws::{
    Config as SockudoConfig, Http3 as SockudoHttp3, Role as SockudoRole,
    Stream as SockudoTransportStream, WebSocketStream as SockudoWebSocketStream,
};

pub(super) use sockudo_ws::{
    Error as SockudoError, Message as SockudoMessage, error::CloseReason as SockudoCloseReason,
};

/// Client-role h3 CONNECT request stream (the h3 side of one WebSocket).
pub(super) type H3RequestStreamHandle = H3RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
/// Handle for opening new request streams on a shared h3 connection.
pub(super) type H3SendRequestHandle = H3SendRequest<h3_quinn::OpenStreams, Bytes>;
/// Sockudo WebSocket running over one h3 CONNECT stream.
pub(super) type RawH3WsStream = SockudoWebSocketStream<SockudoTransportStream<SockudoHttp3>>;

/// RFC 9220 `:protocol = websocket` pseudo-header value for Extended CONNECT
/// requests.
pub(super) fn websocket_protocol() -> h3::ext::Protocol {
    h3::ext::Protocol::WEBSOCKET
}

/// Wraps an established h3 CONNECT request stream into a client-role sockudo
/// WebSocket.
pub(super) fn client_ws_stream(
    stream: H3RequestStreamHandle,
    http3_idle_timeout_ms: u64,
) -> RawH3WsStream {
    let h3_stream = SockudoTransportStream::<SockudoHttp3>::from_h3_client(stream);
    SockudoWebSocketStream::from_raw(
        h3_stream,
        SockudoRole::Client,
        SockudoConfig::builder()
            .http3_idle_timeout(http3_idle_timeout_ms)
            .build(),
    )
}
