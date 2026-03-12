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

## Notes

- The patch files in the repository root are documentation and review artifacts.
- The actual builds use the vendored copies from `vendor/` through `[patch.crates-io]`.
