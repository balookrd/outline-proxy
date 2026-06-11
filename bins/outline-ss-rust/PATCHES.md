# Local Patches

This repository vendors and patches two upstream crates to make the HTTP/3 WebSocket path practical.

*Русская версия: [PATCHES.ru.md](PATCHES.ru.md)*

## h3

Patch file: [h3-rfc9220-websocket.patch](h3-rfc9220-websocket.patch)

Why it is needed:
- upstream `h3 0.0.8` does not recognise `:protocol = websocket`
- RFC 9220 WebSocket over HTTP/3 requires this pseudo-header value for Extended CONNECT

What it changes:
- adds `Protocol::WEBSOCKET`
- teaches `h3` to parse and serialise `websocket` in `:protocol`
- suppresses noisy warnings in the vendored copy

Vendored crate path:
- [vendor/h3](vendor/h3)

Cargo override:
- `[patch.crates-io] h3 = { path = "vendor/h3" }`

## sockudo-ws

Patch file: [sockudo-ws-h3-noerror.patch](sockudo-ws-h3-noerror.patch)

Why it is needed:
- upstream `sockudo-ws 1.7.4` prints `HTTP/3 accept error` / `HTTP/3 connection error` on a clean shutdown with `H3_NO_ERROR`
- this produces false noise on stderr even when the RFC 9220 relay is working correctly

What it changes:
- treats `ApplicationClose: H3_NO_ERROR` as a normal close
- suppresses these false-positive `eprintln!` messages

Vendored crate path:
- [vendor/sockudo-ws](vendor/sockudo-ws)

Cargo override:
- `[patch.crates-io] sockudo-ws = { path = "vendor/sockudo-ws" }`

## fix-h3-poll-write (h3 + sockudo-ws)

Patch file: [fix-h3-poll-write.patch](fix-h3-poll-write.patch)

Why it is needed:
- `AsyncWrite::poll_write` in `sockudo-ws` created a new `send_data` future on
  **every** call, including retries after `Poll::Pending`
- when the QUIC send buffer was temporarily full, h3-quinn set its internal
  `writing = Some(data)` on the first call, but the future was dropped before
  `poll_ready` could flush it; the next `poll_write` called `send_data` again
  while `writing` was still occupied
- h3-quinn detects the double write and returns
  `InternalError("internal error in the http stack")`, which the h3 layer
  translates into `ApplicationClose: H3_INTERNAL_ERROR`, closing the entire QUIC
  connection and killing all multiplexed sessions on it
- the same drop-and-recreate problem existed in `poll_shutdown`: the async
  `finish()` function recreated its future on every call; if the QUIC send buffer
  was full while sending the GREASE frame, `send_data` again saw `writing.is_some()`
  and produced `H3_INTERNAL_ERROR`

What it changes:

**`vendor/h3`** (`src/connection.rs`, `src/server/stream.rs`, `src/client/stream.rs`):
- adds `queue_send(&mut self, buf: B) -> Result<(), StreamError>` — synchronously
  places data into the h3-quinn write buffer (first half of `send_data`)
- adds `poll_drain(&mut self, cx) -> Poll<Result<(), StreamError>>` — polls until
  the write buffer is fully flushed (second half); safe to call repeatedly without
  risk of a double write
- adds `queue_grease(&mut self) -> Result<(), StreamError>` — synchronously enqueues
  a GREASE frame (if `send_grease` is enabled) and clears the flag; no-op if disabled
- adds `poll_quic_finish(&mut self, cx) -> Poll<Result<(), StreamError>>` — polls
  until the QUIC FIN is delivered on the send side; call only after `poll_drain`
  has returned Ready

**`vendor/sockudo-ws`** (`src/stream/transport_stream.rs`, `src/http3/stream.rs`):
- adds `write_queued: Option<usize>` to `Http3StreamInner::Server` and `::Client`
  (and to `Http3ServerStream` / `Http3ClientStream`)
- rewrites `poll_write` as a two-phase state machine: `queue_send` is called exactly
  once per logical write (when `write_queued.is_none()`); subsequent polls after
  Pending go directly to `poll_drain` without touching the h3-quinn write buffer again
- adds `shutdown_started: bool` to the same types
- rewrites `poll_shutdown` as a three-phase state machine: `queue_grease` (once),
  `poll_drain` (flush the GREASE frame or no-op), `poll_quic_finish` (send FIN)

Vendored crate paths:
- [vendor/h3](vendor/h3)
- [vendor/sockudo-ws](vendor/sockudo-ws)

## Notes

- The patch files in the repository root are documentation and review artefacts.
- Actual builds use the vendored copies from `vendor/` via `[patch.crates-io]`.
