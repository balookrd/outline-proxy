# Carrier Padding

*Русская версия: [PADDING.ru.md](PADDING.ru.md)*

Adaptive application-layer padding for the WebSocket / XHTTP carriers. It breaks
the TLS-record-size correlation that "proxy-inside-TLS" (TLS-in-TLS) classifiers
key on, without adopting a second proxy protocol — the same goal AnyTLS's
padding pursues, hardened into the carriers `outline-proxy` already ships.

## Why

When a proxied stream is tunnelled inside TLS (Shadowsocks or VLESS over
WebSocket / XHTTP), each application write tends to map onto one outer TLS
record. The *size* of that record then tracks the size of the inner proxied
chunk. A passive classifier that cannot read the TLS plaintext can still watch
the sequence of record sizes and recognise the tell-tale shape of a proxied
stream nested inside TLS — the heuristic deployed by, among others, Russia's
TSPU. VLESS-over-WS / XHTTP has exactly the same exposure as Shadowsocks, so it
is padded the same way.

Padding decouples the two: every proxied chunk (an encrypted Shadowsocks chunk
or a VLESS frame) is wrapped in a length-delimited frame whose tail is a random
number of throw-away bytes, so the buffer handed to the TLS layer no longer has
a fixed relationship to the payload it carries.

## Frame format

Each frame is `real_len | pad_len | real | pad`:

| Field      | Size            | Meaning                              |
|------------|-----------------|--------------------------------------|
| `real_len` | `u16` big-endian | length of the real proxied bytes     |
| `pad_len`  | `u16` big-endian | length of the pad tail               |
| `real`     | `real_len` bytes | encrypted SS chunk or VLESS frame    |
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
  other path keeps the plain Shadowsocks / VLESS wire. This lets one server pad
  its own clients on one path (SS *or* VLESS) while serving third-party clients
  (including third-party VLESS clients such as xray / sing-box) on another,
  unchanged.
- **Client — global default + per-uplink override.** The global `[padding]`
  block sets the scheme parameters (range / cover / jitter) and a default
  on/off, `enabled`. Each `[[outline.uplinks]]` may override the on/off with
  `padding = true` / `padding = false`: the effective decision for a dial is
  the per-uplink value when set, else the global `enabled` default (the same
  override/fallback shape as the per-uplink `fingerprint_profile`). So an
  operator can leave the global default off and pad only the uplinks pointing
  at their own servers (`padding = true`), or leave it on and exclude a
  specific uplink — e.g. a VLESS uplink to a third-party xray / sing-box server
  — with `padding = false`. A padded dial (SS *and* VLESS, TCP *and* VLESS-UDP)
  must point at a server path that is also padded.

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
- **VLESS-over-WebSocket** — h1, h2, **h3**.
- **VLESS-over-XHTTP** — h1, h2, h3.
- **VLESS-UDP over WebSocket** — padded **per datagram** (one frame wraps one
  packet). This is the one place UDP *is* padded — see below.

VLESS multiplexes TCP and UDP on a *single* path (distinguished by a command
byte inside the first frame), so the server cannot tell the two legs apart
before it reads data. A padded VLESS path therefore has to pad the UDP leg too,
or the server would feed an unframed UDP datagram into the decoder and corrupt
the session. The codec wraps each datagram in exactly one frame, so packet
boundaries survive.

SS does not have this problem in *either* path mode, so its UDP leg always stays
plain:

- **Split SS** — TCP and UDP are *separate* paths; the operator simply leaves
  the UDP path out of `[padding] paths`.
- **Combined SS** — TCP and UDP share one path, but the tcp/udp discriminator
  rides in the URL token (WS) / session id (XHTTP), which the server decodes at
  upgrade time — *before any data* — and dispatches the UDP leg to the unpadded
  relay (`udp_upgrade_for_path` → `run_udp_relay`) while the TCP leg goes to the
  padded `run_tcp_relay`. Both legs resolve the same base path, so listing the
  combined base path in `[padding] paths` pads only the TCP leg; the UDP leg is
  never fed into a decoder.

VLESS has no such pre-data discriminator (its command byte is *inside* the
encrypted-or-not data frame, not in the path/token), which is the one reason its
UDP leg must be padded where SS's never is.

**Out of scope:**

- **SS-UDP over WS / XHTTP** — one Shadowsocks packet per frame; never padded
  in either path mode (split: a path distinct from SS-TCP, left out of
  `[padding] paths`; combined: shares the path with SS-TCP but the server
  decodes the tcp/udp bit at upgrade time and routes the UDP leg to the unpadded
  relay before reading data). Unlike VLESS-UDP, which shares its path with no
  pre-data discriminator and so must be padded.
- **Raw SS / VLESS over QUIC** (ALPN `ss` / `vless`) — a separate transport, not
  a WS carrier; QUIC has its own fingerprint surface (a separate future track).

## Configuration

### Server (`outline-ss-rust`)

```toml
[padding]
enabled = true
paths = ["/SECRET/tcp", "/SECRET/vless"] # WS/XHTTP carrier paths to pad (SS or VLESS)
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
enabled = false              # global default (per-uplink `padding` overrides it)
min_bytes = 0
max_bytes = 256              # max pad per frame (0 = no framing)
cover = false                # idle pad-only cover frames (uplink)
cover_jitter_min_ms = 250
cover_jitter_max_ms = 1500

# Pad only your own server, even with the global default off:
[[outline.uplinks]]
name = "mine"
# … vless_ws_url / tcp_ws_url / etc. …
padding = true               # override: pad this uplink's dials

# Leave a third-party VLESS uplink plain, even with the global default on:
[[outline.uplinks]]
name = "thirdparty"
# … vless_ws_url to an xray / sing-box server …
padding = false              # override: never pad this uplink
```

The `[padding]` block sets the scheme parameters and the global default
(`enabled`); each uplink's `padding` key overrides the on/off for that uplink
(absent → inherit the global default). The default profile (`0..256`) is
light — it breaks exact size correlation at minimal overhead. Raise `max_bytes`
for a wider size distribution at the cost of more bandwidth. Enable `cover` on
both ends together when timing analysis of idle periods is a concern.

## Operational notes

- Roll the gate out to both ends in one change. A half-rolled-out pair (one side
  padding, the other not) fails the affected sessions until both match.
- Padding adds a 4-byte header plus the pad tail per write; on the light profile
  this is a small, bounded overhead. It does not change the negotiated transport,
  ALPN, or TLS handshake.
- Padding is resolved from the startup configuration. Changing `[padding]`
  requires a restart of the affected binary (it is not hot-reloaded).
