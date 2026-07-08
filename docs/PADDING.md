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
  — with `padding = false`. A padded dial (SS and VLESS, TCP and UDP alike)
  must point at server path(s) that are also padded.

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
- **SS-UDP over WebSocket / XHTTP** — padded **per datagram** (one frame wraps
  one encrypted Shadowsocks packet); see *UDP* below.
- **VLESS-over-WebSocket** — h1, h2, **h3**.
- **VLESS-over-XHTTP** — h1, h2, h3.
- **VLESS-UDP over WebSocket** — padded **per datagram** (one frame wraps one
  packet); see *UDP* below.

### UDP

Every UDP carrier is padded the same way, so there is no longer an asymmetry
between SS-UDP and VLESS-UDP. Each datagram is wrapped in exactly one frame —
the codec never splits a packet across datagrams, so packet boundaries survive —
and the receiver runs each inbound datagram through a streaming decoder before
the SS / VLESS layer parses it. A `real_len = 0` cover frame on a quiet downlink
decodes to nothing and is dropped.

- **VLESS-UDP** multiplexes TCP and UDP on a *single* path (distinguished by a
  command byte *inside* the first frame), so the server cannot tell the legs
  apart before it reads data — a padded VLESS path therefore *must* pad the UDP
  leg too.
- **Split SS** routes TCP and UDP on *separate* paths. List both in
  `[padding] paths` to pad the whole uplink. The client's per-uplink switch is
  all-or-nothing — a padded uplink frames every datagram it sends — so a padded
  SS uplink expects both its TCP and UDP server paths to be padded.
- **Combined SS** puts TCP and UDP on one base path, split by a hidden token
  (WS) / session-id (XHTTP) bit the server decodes at upgrade time. Both legs
  resolve the same base path, so listing the combined base path in
  `[padding] paths` pads *both* legs: the UDP leg's `run_udp_relay` resolves the
  same per-path scheme as the TCP leg's `run_tcp_relay`.

## Downstream-throttle detection (server → client uplink switch)

A padded carrier can optionally watch its own throughput and, when a provider
starts shaping the path toward the client (e.g. a VPS throttling traffic toward
Russia), nudge the client to move to another uplink — before the user notices
the slowdown. It covers **both TCP and UDP** carriers on both transports:
VLESS and SS over WS / XHTTP. This matters for QUIC (HTTP/3) traffic such as
YouTube, which rides the UDP carrier — a UDP-only throttle is detected on the
UDP carrier and switches the UDP leg of the same uplink. The unpadded wire is
never monitored.

The server measures, per carrier, the rate it pulls from the internet (inbound,
destined for the client) versus the rate it hands to the carrier (outbound),
plus whether a send backlog is present. When inbound keeps outrunning outbound
by the configured ratio (default 2×) *with* a backlog, sustained over several
windows, it emits one **control cover frame** — a `real_len = 0` frame whose pad
begins with a magic `OCTL` prefix. A padding-unaware peer drops it like any
cover frame; a client that opted in (`react_to_throttle = true`) decodes the
signal, applies a temporary penalty + cooldown to the current uplink, and
health-weighted selection migrates its traffic to another uplink. The cooldown
is temporary — the uplink recovers automatically once its probe goes green.

Because the signal rides a cover frame, the feature only works on a **padded
carrier** — only your own clients on a path you listed in `[padding] paths` can
receive it; third-party (unpadded) SS clients and the unpadded datagram paths
are never monitored. Both detection (server) and reaction (client) are **off by
default**. "Switch
uplink" only helps when the other uplink takes a different network path (a
different server / VPS) — that is the operator's uplink layout, not something
the code can ensure. The server cannot perfectly tell provider throttling from a
genuinely slow client last-mile; the ratio + backlog + sustain + minimum-rate
gates keep false positives down, but tune them to your traffic.

## Configuration

### Server (`outline-ss-rust`)

```toml
[padding]
enabled = true
# WS/XHTTP carrier paths to pad. SS-TCP, SS-UDP, the combined SS base path, and
# VLESS all ride the same per-path switch; list the SS-UDP path too to pad the
# UDP leg uniformly.
paths = ["/SECRET/tcp", "/SECRET/udp", "/SECRET/vless"]
min_bytes = 0                            # min pad drawn per frame
max_bytes = 256                          # max pad per frame (0 = no framing)
cover = false                            # idle pad-only cover frames (downlink)
cover_jitter_min_ms = 250                # idle-gap floor before a cover frame
cover_jitter_max_ms = 1500               # idle-gap ceiling

# Downstream-throttle detection (padded VLESS-over-WS only). Off by default.
throttle_detect_enabled = false          # watch throughput, nudge client to switch uplink
throttle_ratio_percent = 200             # signal when inbound >= 2x outbound (200 = 2x)
throttle_window_secs = 1                 # sampling window
throttle_sustain_windows = 5             # consecutive over-threshold windows before signalling
throttle_min_bytes_per_sec = 1000000     # inbound floor (~8 Mbit/s); below this not actionable
throttle_signal_cooldown_secs = 30       # min gap between signals on one carrier
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
