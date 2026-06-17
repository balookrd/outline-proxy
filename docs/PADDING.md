# Carrier Padding

*Русская версия: [PADDING.ru.md](PADDING.ru.md)*

Adaptive application-layer padding for the WebSocket / XHTTP carriers. It breaks
the TLS-record-size correlation that "proxy-inside-TLS" (TLS-in-TLS) classifiers
key on, without adopting a second proxy protocol — the same goal AnyTLS's
padding pursues, hardened into the carriers `outline-proxy` already ships.

## Why

When a Shadowsocks stream is tunnelled inside TLS (SS-over-WebSocket,
SS-over-XHTTP), each application write tends to map onto one outer TLS record.
The *size* of that record then tracks the size of the inner Shadowsocks chunk.
A passive classifier that cannot read the TLS plaintext can still watch the
sequence of record sizes and recognise the tell-tale shape of a proxied stream
nested inside TLS — the heuristic deployed by, among others, Russia's TSPU.

Padding decouples the two: every Shadowsocks chunk is wrapped in a
length-delimited frame whose tail is a random number of throw-away bytes, so the
buffer handed to the TLS layer no longer has a fixed relationship to the payload
it carries.

## Frame format

Each frame is `real_len | pad_len | real | pad`:

| Field      | Size            | Meaning                              |
|------------|-----------------|--------------------------------------|
| `real_len` | `u16` big-endian | length of the real Shadowsocks bytes |
| `pad_len`  | `u16` big-endian | length of the pad tail               |
| `real`     | `real_len` bytes | the encrypted Shadowsocks chunk      |
| `pad`      | `pad_len` bytes  | random bytes, discarded on decode    |

The codec lives in `crates/outline-wire/src/padding.rs` and is pure framing —
no RNG and no clock; the caller (the transport layer) supplies both the pad
bytes and the random draw that sizes them, mirroring the SS2022 header codec.
The decoder (`PaddingDecoder`) is a streaming state machine: input may be split
at any byte boundary, because h2 / h3 DATA frames carry no relation to frame
edges. A `real_len = 0` frame carries pad only — that is the **cover frame**
shape (see below); the decoder yields nothing for it.

Both `real` and `pad` are capped at 65535 bytes (the `u16` ceiling); the
transport chunks a larger write to that bound before framing, and only the final
chunk of a write carries pad, so one transport write produces one random-sized
tail regardless of how many segments it took.

## Gate: config-synchronised, not negotiated

There is **no on-wire capability bit**. A peer that has not enabled padding
simply never frames its writes and never decodes; a peer that has will feed a
plain (unframed) stream into the decoder and fail. So **both ends must opt in
together** — exactly like cross-transport session resumption. The default is
disabled, which keeps the wire byte-for-byte identical to the unpadded carrier,
so third-party clients (Happ, Outline, xray, sing-box) are unaffected until an
operator turns padding on.

- **Server — per-path.** `[padding] paths` lists the carrier paths that are
  padded. Only connections whose matched path is in that set are framed; every
  other path keeps the plain Shadowsocks-over-WS / XHTTP wire. This lets one
  server pad its own clients on one path while serving third-party clients on
  another, unchanged.
- **Client — global.** The client is always "ours", so the knob is a single
  process-wide value: when enabled, every WS / XHTTP dial is padded. It must
  point at a server path that is also padded.

## Cover traffic

With `cover = true`, a quiet connection emits pad-only **cover frames**
(`real_len = 0`) at a jittered interval drawn uniformly from
`[cover_jitter_min_ms, cover_jitter_max_ms]`, so silence does not leak timing.
The timer resets after every real write, so cover frames fire only on a
genuinely idle link and never interleave with live traffic. The client emits
cover on the uplink writer; the server on the downlink writer. A cover frame is
a binary data frame (never a WebSocket Ping), so it is safe on the H3 carrier —
it cannot escalate to the connection-level `H3_INTERNAL_ERROR` a server-
originated Ping risks. The receiver's decoder drops cover frames transparently.

## Covered carriers

Padding rides the `Message` layer shared by every WS / XHTTP carrier, so one
mechanism covers them all:

- **SS-over-WebSocket** — h1, h2, **h3** (WebSocket-over-HTTP/3, RFC 9220).
- **SS-over-XHTTP** — h1, h2, h3.

**Out of scope:**

- **UDP carriers** (SS-UDP over WS / XHTTP) — one Shadowsocks packet per frame;
  padding is a TCP-stream feature and is not applied.
- **Raw SS / VLESS over QUIC** (ALPN `ss` / `vless`) — a separate transport, not
  a WS carrier; QUIC has its own fingerprint surface (a separate future track).
- **VLESS** carriers are not padded.

## Configuration

### Server (`outline-ss-rust`)

```toml
[padding]
enabled = true
paths = ["/SECRET/tcp", "/SECRET/ss"]   # WS/XHTTP carrier paths to pad
min_bytes = 0                            # min pad drawn per frame
max_bytes = 256                          # max pad per frame (0 = no framing)
cover = false                            # idle pad-only cover frames (downlink)
cover_jitter_min_ms = 250                # idle-gap floor before a cover frame
cover_jitter_max_ms = 1500               # idle-gap ceiling
```

Validation rejects `enabled = true` with an empty `paths`.

### Client (`outline-ws-rust`)

```toml
[padding]
enabled = true
min_bytes = 0
max_bytes = 256              # max pad per frame (0 = no framing)
cover = false                # idle pad-only cover frames (uplink)
cover_jitter_min_ms = 250
cover_jitter_max_ms = 1500
```

The default profile (`0..256`) is light — it breaks exact size correlation at
minimal overhead. Raise `max_bytes` for a wider size distribution at the cost of
more bandwidth. Enable `cover` on both ends together when timing analysis of
idle periods is a concern.

## Operational notes

- Roll the gate out to both ends in one change. A half-rolled-out pair (one side
  padding, the other not) fails the affected sessions until both match.
- Padding adds a 4-byte header plus the pad tail per write; on the light profile
  this is a small, bounded overhead. It does not change the negotiated transport,
  ALPN, or TLS handshake.
- Padding is resolved from the startup configuration. Changing `[padding]`
  requires a restart of the affected binary (it is not hot-reloaded).
