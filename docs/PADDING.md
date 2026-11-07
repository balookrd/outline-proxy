# Carrier padding

*Русская версия: [PADDING.ru.md](PADDING.ru.md)*

Application-layer padding for the WebSocket / XHTTP carriers. It breaks the
TLS-record-size correlation that "proxy-inside-TLS" (TLS-in-TLS) classifiers key
on, without adding a second proxy protocol — the same goal as AnyTLS padding,
implemented inside the carriers `outline-proxy` already has.

## What padding hides

When a proxied stream is tunnelled inside TLS (Shadowsocks or VLESS over
WebSocket / XHTTP), each application write tends to map onto one outer TLS
record. The size of that record then tracks the size of the inner proxied
chunk. A passive classifier that cannot read the TLS plaintext can still watch
the sequence of record sizes and recognise a proxied stream nested inside TLS;
Russia's TSPU uses this heuristic, among others. VLESS over WS / XHTTP is
exposed the same way as Shadowsocks, so it is padded the same way.

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

The codec lives in `crates/outline-wire/src/padding.rs` and does framing only,
with no RNG and no clock: the caller (the transport layer) supplies the pad
bytes and the random draw that sizes them, as with the SS2022 header codec.
The decoder (`PaddingDecoder`) is a streaming state machine: input may be split
at any byte boundary, because h2 / h3 DATA frames are not aligned with frame
edges. A `real_len = 0` frame carries pad only; that is the cover frame shape
(see below), and the decoder yields nothing for it.

Both `real` and `pad` are capped at 65535 bytes (the `u16` ceiling). The
transport cuts a larger write into chunks of at most that size before framing,
and only the final chunk of a write carries pad, so one transport write produces
one random-sized tail regardless of how many segments it took.

## Gate: config-synchronised, not negotiated

There is no capability bit on the wire. A peer with padding disabled never
frames its writes and never decodes; a peer with padding enabled feeds a plain
(unframed) stream into the decoder and fails. Both ends must therefore enable
padding together, as with cross-transport session resumption. The default is
disabled: the byte stream then carries no padding frames (early-session shaping
still splits the first messages on h1/h2, but a stream reader sees the same
bytes), so third-party clients (Happ, Outline, xray, sing-box) keep working
until an operator turns padding on.

- Server, per endpoint. Padding is an attribute of the endpoint:
  `[[endpoint]] padded = true` marks one carrier path as padded. Only
  connections on a `padded` endpoint are framed; every other endpoint keeps
  the plain Shadowsocks / VLESS wire. `[padding]` holds only the scheme's
  parameters (range, cover, jitter, throttle detection), not the list of padded
  paths. One server can thus pad its own clients on one endpoint (SS or VLESS)
  and serve third-party clients, including VLESS clients such as xray /
  sing-box, unchanged on another, unpadded endpoint.
- Client, global default plus per-uplink override. The global `[padding]` block
  sets the scheme parameters (range, cover, jitter) and the default on/off,
  `enabled`. Each `[[outline.uplinks]]` entry may override it with
  `padding = true` / `padding = false`: a dial uses the per-uplink value when it
  is set, otherwise the global `enabled` (the same override/fallback as the
  per-uplink `fingerprint_profile`). An operator can leave the global default
  off and pad only the uplinks pointing at their own servers
  (`padding = true`), or turn it on and exclude a specific uplink, for example
  a VLESS uplink to a third-party xray / sing-box server, with
  `padding = false`. A padded dial (SS and VLESS, TCP and UDP alike) must point
  at server paths that are padded too.

## Cover traffic

With `cover = true`, an idle connection emits pad-only cover frames
(`real_len = 0`) at an interval drawn uniformly from
`[cover_jitter_min_ms, cover_jitter_max_ms]`, so periods of silence do not show
in the timing. The timer resets after every real write, so cover frames fire
only on an idle link and never interleave with live traffic. The client emits
cover on the uplink writer, the server on the downlink writer. A cover frame is
a binary data frame, never a WebSocket Ping, so it is safe on the H3 carrier:
it cannot escalate to the connection-level `H3_INTERNAL_ERROR` that a
server-originated Ping can cause. The receiver's decoder drops cover frames.

## Early-session shaping

A length-based classifier sees the first bytes of a TCP session best: a
TLS-in-tunnel handshake leaves as a few records of characteristic sizes. On h1 /
h2 TCP sessions, padded or not, the first messages are therefore cut into
pieces in both directions (constants in `crates/outline-wire/src/early_shape.rs`):

| Parameter | Value |
|---|---|
| Window, per session | first 6..=10 messages or first 16..=24 KiB, whichever comes first; after that the session is unshaped |
| Client → server | a message larger than 900 B is split into pieces of 300..=850 B |
| Lead-in covers (client → server, padded path only) | with probability 1/2 per session, 1-2 pad-only frames of 40..=100 B of pad each before the first split message |
| Server → client | a message larger than 1500 B is split into pieces of 600..=2800 B |

On an XHTTP carrier in packet-up mode every client write is its own POST, so
the messages are not cut into more POSTs. On `xhttp_h2` the body of each POST in
the window is cut into DATA frames of the same sizes instead (same bytes and
`Content-Length`, no covers); this applies to UDP riding packet-up POSTs too,
and each POST still carries one datagram whole. `xhttp_h1` packet-up leaves the
start of the session as is.

On a padded path each piece is an ordinary padded frame with its own random pad
tail, so the receiver's decoder does not change. On an unpadded path each piece
is a plain `Binary` message with no framing: receivers read TCP as a stream, so
the bytes are the same and only the message boundaries differ. There are no
config keys: shaping is on for every h1 / h2 TCP session; covers need padding.

### What applies regardless of padding

Early-session shaping (the cutting, not the covers) needs no padding. Five more
changes remove markers of the carrier itself and are always on:

- h2: one TLS record per frame. The client's h2 IO forwards vectored writes,
  so a frame header and its payload leave in one record instead of two.
- h2: server downlink messages fit one record. On h2 carriers the server
  keeps each TCP downlink message (SS, VLESS, VLESS mux, resume replay) within
  one DATA frame of at most 16375 B, so the frame and its 9-byte header leave as
  one TLS record (no 16401 + 26 record pairs on bulk downloads). The upstream
  read itself is bounded, so no small remainder message is left to be written
  together with the next full frame. UDP datagrams and cover frames are not cut
  (they are small); a pad range that leaves under 1 KiB of data per message
  (`max_bytes` above ~15 KiB) turns this limit off.
- h2: client uplink messages fit one record. The mirror of the server's
  limit: on `ws_h2` and XHTTP stream-one over h2 the client cuts an uplink
  message (SS or VLESS, up to 256 KiB coalesced) that would not fit one DATA
  frame of at most 16375 B, WS header and padding at the scheme's largest pad
  included, into even pieces that do, so bulk uploads leave no 16401 + 26
  record pairs either. The tail of a large first write past the shaping
  window's byte budget is cut the same way. Not on h1, h3 or XHTTP packet-up
  (each write there is its own POST, cut by its own DATA-frame shaping).
- VLESS response header with the first data. The server never sends the
  2-byte `[VERSION, 0x00]` response header (21 B once padded) as a message of
  its own, on any path. A fresh TCP session, a resume without control frames,
  a relayed (cluster edge) session and VLESS-UDP (fresh, resumed or relayed)
  send it together with the first upstream bytes or the first response packet;
  a VLESS-mux session sends it in front of its first downlink mux frame,
  whichever sub-connection sends that frame. A resume that asked for the
  Ack-Prefix v1 / v2 replay frames sends the header in the same message as
  those frames (the client waits for them before it resumes its uplink, so they
  cannot wait for upstream data). The header is never captured into the v2
  replay ring.
- SS2022 request header with the first data. On h1 / h2 carriers the
  client holds the request header for up to 50 ms (`SS2022_HEADER_HOLD`) so
  that it leaves together with the first data. Not on h3 (there is no TLS record
  shape to protect, and the hold would only delay server-speaks-first
  protocols) and not in uplink probes, whose measured latency it would skew.

### Out of scope

h3 (QUIC has its own packetisation), UDP, and timing: shaping changes sizes
only, not the delays between messages (cover frames aside).

### Compatibility

The wire format is unchanged: pieces are normal padding frames (plain `Binary`
messages on an unpadded path), and the bundled writes are ordinary byte
streams. Old peers interoperate in both directions; they do not shape their own
side.

## Covered carriers

Padding works on the `Message` layer shared by every WS / XHTTP carrier, so one
mechanism covers them all:

- SS over WebSocket: h1, h2, h3 (WebSocket over HTTP/3, RFC 9220).
- SS over XHTTP: h1, h2, h3.
- SS-UDP over WebSocket / XHTTP: padded per datagram (one frame wraps one
  encrypted Shadowsocks packet); see [UDP](#udp) below.
- VLESS over WebSocket: h1, h2, h3.
- VLESS over XHTTP: h1, h2, h3.
- VLESS-UDP over WebSocket: padded per datagram (one frame wraps one packet);
  see [UDP](#udp) below.

### UDP

Every UDP carrier is padded the same way, SS-UDP and VLESS-UDP alike. Each
datagram is wrapped in exactly one frame (the codec never splits a packet across
datagrams, so packet boundaries survive), and the receiver runs each inbound
datagram through a streaming decoder before the SS / VLESS layer parses it. A
`real_len = 0` cover frame on an idle downlink decodes to nothing and is
dropped.

"One datagram, one frame" holds only while the carrier itself preserves packet
boundaries: true on WebSocket, false on XHTTP, whose payload is an HTTP byte
stream. SS-UDP over XHTTP therefore wraps the padded or bare datagram in a
length-prefixed record of its own; padding sits inside that record, and the two
work in any combination. See
[SS-UDP record framing over XHTTP](XHTTP-UDP-RECORDS.md).

- VLESS-UDP multiplexes TCP and UDP on a single path (distinguished by a
  command byte inside the first frame), so the server cannot tell the legs
  apart before it reads data. A padded VLESS path therefore must pad the UDP
  leg too.
- Split SS routes TCP and UDP on separate endpoints (`ws_ss_tcp` /
  `ws_ss_udp`, or `xhttp_ss_tcp` / `xhttp_ss_udp`). Set `padded = true` on both
  to pad the whole uplink. The client's per-uplink switch is all-or-nothing (a
  padded uplink frames every datagram it sends), so a padded SS uplink expects
  both its TCP and UDP server endpoints to be padded.
- Combined SS (`ws_ss` / `xhttp_ss`) puts TCP and UDP on one endpoint, split
  by a hidden token (WS) / session-id (XHTTP) bit that the server decodes at
  upgrade time. Both legs resolve the same endpoint, so `padded = true` on a
  combined endpoint pads both legs: the UDP leg's `run_udp_relay` resolves the
  same per-path scheme as the TCP leg's `run_tcp_relay`.

## Downstream-throttle detection (server → client uplink switch)

A padded carrier can watch its own throughput and, when a provider starts
shaping the path toward the client (for example, a VPS throttling traffic toward
Russia), tell the client to move to another uplink. It covers TCP and UDP
carriers on both transports: VLESS and SS over WS / XHTTP. For QUIC (HTTP/3)
traffic such as YouTube, which rides the UDP carrier, a UDP-only throttle is
detected on the UDP carrier and switches the UDP leg of the same uplink. The
unpadded wire is never monitored.

The server measures, per carrier, the rate it pulls from the internet (inbound,
destined for the client) and the rate it hands to the carrier (outbound), and
whether a send backlog is present. When inbound outruns outbound by
`throttle_ratio_percent` (default 200, i.e. 2×) with a backlog, for
`throttle_sustain_windows` consecutive windows, and inbound is at least
`throttle_min_bytes_per_sec`, the server emits one control cover frame: a
`real_len = 0` frame whose pad begins with the magic prefix `OCTL`. A peer that
does not act on the signal drops it like any cover frame. A client with
`react_to_throttle = true` decodes the signal, applies a temporary penalty and
cooldown to the current uplink, and health-weighted selection moves its traffic
to another uplink. The uplink returns to selection once its probe passes again.

Because the signal rides a cover frame, it reaches only your own clients on an
endpoint with `padded = true`; third-party (unpadded) SS clients and unpadded
endpoints are never monitored. Detection (server) and reaction (client) are
both off by default. Switching uplinks helps only when the other uplink takes a
different network path (a different server / VPS); that depends on the
operator's uplink layout, not on the code. The server cannot always tell
provider throttling from a slow last mile on the client side; the ratio,
backlog, sustain and minimum-rate thresholds limit false positives, so tune
them to your traffic.

## Configuration

### Server (`outline-ss-rust`)

```toml
# Mark the endpoints you want padded — SS-TCP, SS-UDP, the combined SS
# endpoint, and VLESS all use the same `padded` attribute; set it on the
# SS-UDP endpoint too to pad the UDP leg uniformly.
[[endpoint]]
path = "/SECRET/tcp"
kind = "ws_ss_tcp"
padded = true

[[endpoint]]
path = "/SECRET/udp"
kind = "ws_ss_udp"
padded = true

[[endpoint]]
path = "/SECRET/vless"
kind = "ws_vless"
padded = true

# Parameters only — an endpoint pads iff its own `padded = true` (above), not
# a key in this block.
[padding]
min_bytes = 0                            # min pad drawn per frame
max_bytes = 256                          # max pad per frame (0 = no framing)
cover = false                            # idle pad-only cover frames (downlink)
cover_jitter_min_ms = 250                # idle-gap floor before a cover frame
cover_jitter_max_ms = 1500               # idle-gap ceiling

# Downstream-throttle detection (padded SS/VLESS, TCP+UDP, WS/XHTTP). Off by default.
throttle_detect_enabled = false          # watch throughput, nudge client to switch uplink
throttle_ratio_percent = 200             # signal when inbound >= 2x outbound (200 = 2x)
throttle_window_secs = 1                 # sampling window
throttle_sustain_windows = 5             # consecutive over-threshold windows before signalling
throttle_min_bytes_per_sec = 1000000     # inbound floor (~8 Mbit/s); below this not actionable
throttle_signal_cooldown_secs = 30       # min gap between signals on one carrier
```

`max_bytes` below `min_bytes` is raised to `min_bytes`, and
`cover_jitter_max_ms` below `cover_jitter_min_ms` is raised to the minimum.

Deprecated: `throttle_edge_min_bytes_per_sec` set the floor of the cluster
edge's stall detector, which was removed together with the v4 mesh relay (see
[`CLUSTER.md`](CLUSTER.md)). The key is still accepted and ignored: the
`[padding]` section rejects unknown keys, so removing it from the schema would
stop a config that still sets it from loading. A config that sets it logs
`ignoring retired padding.throttle_edge_min_bytes_per_sec` at startup. Remove
the key; the field itself goes in a later release.

### Client (`outline-ws-rust`)

```toml
[padding]
enabled = false              # global default (per-uplink `padding` overrides it)
min_bytes = 0
max_bytes = 256              # max pad per frame (0 = no framing)
cover = false                # idle pad-only cover frames (uplink)
cover_jitter_min_ms = 250
cover_jitter_max_ms = 1500
react_to_throttle = false    # act on a server throttle signal (penalise + switch uplink)

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
(absent: inherit the global default). With the default range `0..256`, each
padded write grows by a 4-byte header plus 0..256 bytes of pad. Raise
`max_bytes` for a wider size distribution at the cost of more bandwidth. Enable
`cover` on both ends together when timing analysis of idle periods is a
concern.

## Rollout and overhead

- Enable padding on both ends in one change. A half-rolled-out pair (one side
  padding, the other not) fails the affected sessions until both match.
- Padding adds a 4-byte header plus the pad tail per write. It does not change
  the negotiated transport, ALPN or TLS handshake.
- Padding is read from the startup configuration. Changing `[padding]`
  requires a restart of the affected binary; it is not hot-reloaded.
