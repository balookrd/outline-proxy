// Gate module for the locally patched vendored crates (`vendor/h3`,
// `vendor/sockudo-ws`) — server side.  Every API whose shape or behaviour
// exists only in the patched copies is reached through here, so a rebase of
// the vendored crates onto a new upstream starts at this file plus its
// client-side twin (`crates/outline-transport/src/h3/vendored.rs`).  The
// patches themselves are documented in the root PATCHES.md.
//
// Patched surface funneled through this module:
//   - `WebSocketServer::into_parts` — removed upstream, restored by
//     `sockudo-ws-1.7.5.patch` for the accept loop in `server::h3`.
//   - the `h3::ext::Protocol` request extension — upstream h3 0.0.8 never
//     parses `:protocol = websocket`, so the extension shows up on CONNECT
//     requests only because of the RFC 9220 part of `h3-0.0.8.patch`.
//   - `Stream::from_h3_server` + `WebSocketStream::from_raw` — the write
//     path of the resulting stream relies on the fix-h3-poll-write patch
//     pair (h3 `queue_send`/`poll_drain`/`queue_grease`/`poll_quic_finish`
//     driven by sockudo's `write_queued`/`shutdown_started` state machines).
//
// The type re-exports below are plain upstream API, funneled anyway so the
// rest of the server never names the vendored crates directly (CI-enforced
// for sockudo-ws; server tests are exempt — they impersonate the client).

use bytes::Bytes;

pub(in crate::server) use sockudo_ws::{
    Config as H3WebSocketConfig, Error as H3WsError,
    ExtendedConnectRequest as H3ExtendedConnectRequest, Http3 as H3Transport, Message as H3Message,
    SplitReader as H3SplitReader, SplitWriter as H3SplitWriter, Stream as H3Stream,
    WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
    build_extended_connect_error, build_extended_connect_response,
    error::CloseReason as H3CloseReason,
};

/// Server-role h3 CONNECT request stream (the h3 side of one WebSocket).
pub(in crate::server) type H3ServerRequestStream =
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub(in crate::server) fn h3_ws_server_from_endpoint(
    endpoint: quinn::Endpoint,
    ws_config: H3WebSocketConfig,
) -> H3WebSocketServer<H3Transport> {
    H3WebSocketServer::<H3Transport>::from_endpoint(endpoint, ws_config)
}

pub(in crate::server) fn h3_ws_server_into_parts(
    server: H3WebSocketServer<H3Transport>,
) -> (quinn::Endpoint, H3WebSocketConfig) {
    server.into_parts()
}

/// Wraps an accepted h3 CONNECT request stream into a server-role sockudo
/// WebSocket.
pub(in crate::server) fn server_ws_stream(
    stream: H3ServerRequestStream,
    ws_config: H3WebSocketConfig,
) -> H3WebSocketStream<H3Stream<H3Transport>> {
    let h3_stream = H3Stream::<H3Transport>::from_h3_server(stream);
    H3WebSocketStream::from_raw(h3_stream, sockudo_ws::Role::Server, ws_config)
}

/// Extracts the RFC 9220 `:protocol` pseudo-header value from an Extended
/// CONNECT request, parsed into the extensions by the patched h3.
pub(in crate::server) fn request_websocket_protocol(
    request: &axum::http::Request<()>,
) -> Option<String> {
    request
        .extensions()
        .get::<h3::ext::Protocol>()
        .map(|protocol: &h3::ext::Protocol| protocol.as_str().to_owned())
}
