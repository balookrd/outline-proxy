# Local Patches

This repository currently vendors and patches two upstream crates to make the HTTP/3 WebSocket path practical.

## h3

Patch file: [h3-rfc9220-websocket.patch](/Users/mmalykhin/Documents/outline-ss-rust/h3-rfc9220-websocket.patch)

Why it exists:
- upstream `h3 0.0.8` does not recognize `:protocol = websocket`
- RFC 9220 WebSocket over HTTP/3 needs that pseudo-header value for Extended CONNECT

What it changes:
- adds `Protocol::WEBSOCKET`
- teaches `h3` to parse and serialize `websocket` in `:protocol`
- suppresses some noisy warnings in the vendored copy

Vendored path:
- [vendor/h3](/Users/mmalykhin/Documents/outline-ss-rust/vendor/h3)

Cargo override:
- `[patch.crates-io] h3 = { path = "vendor/h3" }`

## sockudo-ws

Patch file: [sockudo-ws-h3-noerror.patch](/Users/mmalykhin/Documents/outline-ss-rust/sockudo-ws-h3-noerror.patch)

Why it exists:
- upstream `sockudo-ws 1.7.4` prints `HTTP/3 accept error` / `HTTP/3 connection error` for normal `H3_NO_ERROR` shutdowns
- this creates misleading stderr noise even when RFC 9220 relay works correctly

What it changes:
- treats `ApplicationClose: H3_NO_ERROR` as a normal close
- suppresses those false-positive `eprintln!` messages

Vendored path:
- [vendor/sockudo-ws](/Users/mmalykhin/Documents/outline-ss-rust/vendor/sockudo-ws)

Cargo override:
- `[patch.crates-io] sockudo-ws = { path = "vendor/sockudo-ws" }`

## fix-h3-poll-write (h3 + sockudo-ws)

Patch file: [fix-h3-poll-write.patch](fix-h3-poll-write.patch)

Why it exists:
- `AsyncWrite::poll_write` in `sockudo-ws` created a new `send_data` future on
  **every** call, including retries after `Poll::Pending`
- when the QUIC send buffer was momentarily full, h3-quinn set its internal
  `writing = Some(data)` on the first call but the future was dropped before
  `poll_ready` could drain it; the next `poll_write` called `send_data` again
  while `writing` was still occupied
- h3-quinn detects the double-write and returns
  `InternalError("internal error in the http stack")`, which the h3 layer
  propagates as `ApplicationClose: H3_INTERNAL_ERROR`, closing the entire QUIC
  connection and killing all multiplexed sessions on it

What it changes:

**`vendor/h3`** (`src/connection.rs`, `src/server/stream.rs`, `src/client/stream.rs`):
- adds `queue_send(&mut self, buf: B) -> Result<(), StreamError>` — synchronously
  places data into the h3-quinn write buffer (the first half of `send_data`)
- adds `poll_drain(&mut self, cx) -> Poll<Result<(), StreamError>>` — polls until
  the write buffer is fully flushed (the second half), safe to call repeatedly
  without triggering the double-write error

**`vendor/sockudo-ws`** (`src/stream/transport_stream.rs`, `src/http3/stream.rs`):
- adds `write_queued: Option<usize>` to `Http3StreamInner::Server` and `::Client`
- rewrites `poll_write` as a two-phase state machine: `queue_send` is called only
  once per logical write (when `write_queued.is_none()`); subsequent polls after
  `Pending` go straight to `poll_drain`, never touching the h3-quinn write buffer
  a second time

Vendored paths:
- [vendor/h3](vendor/h3)
- [vendor/sockudo-ws](vendor/sockudo-ws)

## Notes

- The patch files in the repository root are documentation and review artifacts.
- The actual builds use the vendored copies from `vendor/` through `[patch.crates-io]`.
