# Uplink Configurations and Fallback Behavior

Defines the six supported `[[outline.uplinks]]` shapes, with a minimal
config block and the dial-time fallback chain for each.

Each fallback step fires only when the previous step returns an error
during the dial / handshake. Once an "advanced" mode (`ws_h3`, `quic`,
`xhttp_h3`) fails for an uplink, a per-uplink **downgrade window** opens:
subsequent dials within the window skip the broken mode entirely. The
window closes when an explicit recovery probe confirms the advanced mode
is reachable again — at that point the uplink is restored to the
configured mode.

*Russian version: [UPLINK-CONFIGURATIONS.ru.md](UPLINK-CONFIGURATIONS.ru.md)*

---

## 1. Native Shadowsocks

Direct TCP / UDP sockets to the SS server. No HTTP, no WebSocket, no QUIC.

```toml
[[outline.uplinks]]
name = "ss-native"
group = "main"
transport = "shadowsocks"
tcp_addr = "ss.example.com:8388"
udp_addr = "ss.example.com:8388"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0
```

- **TCP fallback:** none. Dial failure surfaces as an uplink failure.
- **UDP fallback:** none.
- **Resume:** not used (SS over plain sockets has no session-id concept).

## 2. Shadowsocks over raw QUIC

`tcp_mode = "quic"` selects the raw-QUIC carrier (ALPN `ss`). One QUIC
bidi per SS-TCP session; SS-UDP rides QUIC datagrams 1:1 with SS-AEAD
packets. The dial URL is reused as the QUIC dial target — only
`host:port` matter, scheme and path are ignored.

```toml
[[outline.uplinks]]
name = "ss-quic"
group = "main"
transport = "ws"
tcp_ws_url = "https://ss.example.com:443"
udp_ws_url = "https://ss.example.com:443"
tcp_mode = "quic"
udp_mode = "quic"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0
```

- **TCP fallback chain:** `quic → ws_h2 → ws_h1`.
  - QUIC handshake fails → `note_advanced_mode_dial_failure` opens the
    per-uplink downgrade window; the dispatcher falls into the WS path
    where `effective_tcp_mode` now returns `WsH2`.
  - The h2 handshake fails on the same dial →
    `connect_websocket_with_resume` falls through to `ws_h1` inline.
  - During the downgrade window every new TCP dial skips QUIC entirely
    and starts at H2.
- **UDP fallback chain:** `quic → ws_h2 → ws_h1`. Same shape as TCP.
  SS-UDP over WS uses the WS datagram framing on the H2/H1 stream.
- **Resume:** TCP and UDP each get their own slot in
  `global_resume_cache` (keys `<uplink>#tcp` / `<uplink>#udp`). The
  Session ID survives the carrier switch — a parked upstream
  re-attaches across the QUIC→WS pivot.

## 3. Shadowsocks over WebSocket (H3)

WebSocket carrier on HTTP/1.1, /2, or /3. `ws_h3` (alias `h3`) is
recommended when the server supports it — H3 dials are a single 1-RTT
QUIC handshake versus TCP+TLS+HTTP for H2.

```toml
[[outline.uplinks]]
name = "ss-ws-h3"
group = "main"
transport = "ws"
tcp_ws_url = "wss://example.com/SECRET/tcp"
udp_ws_url = "wss://example.com/SECRET/udp"
tcp_mode = "h3"
udp_mode = "h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0
```

- **TCP fallback chain:** `ws_h3 → ws_h2 → ws_h1`. Inline fallback
  inside `connect_websocket_with_resume`. Each step is a fresh
  handshake on the same `tcp_ws_url`. Failure of `ws_h3` also records a
  host-level cap in `ws_mode_cache`, so subsequent dials within the
  cache TTL skip H3 even before the per-uplink downgrade window kicks
  in.
- **UDP fallback chain:** `ws_h3 → ws_h2 → ws_h1`. Same logic on the
  UDP-WS path.
- **Resume:** TCP and UDP each get their own slot in
  `global_resume_cache` (`<uplink>#tcp` / `<uplink>#udp`). Inline
  H3→H2→H1 fallback inside `connect_websocket_with_resume` carries the
  same `resume_request` token across all three carriers.

## 4. VLESS over raw QUIC

`vless_mode = "quic"` selects raw QUIC with ALPN `vless`. Multiple TCP
and UDP sessions to different targets share a single QUIC connection;
UDP sessions are demuxed by a 4-byte server-allocated session_id
prefix on each datagram. URL is taken from `vless_ws_url`
(only `host:port` matter — same as SS-over-QUIC).

```toml
[[outline.uplinks]]
name = "vless-quic"
group = "main"
transport = "vless"
vless_ws_url = "https://vless.example.com:443"
vless_mode = "quic"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 1.0
```

- **TCP fallback chain:** `quic → ws_h2 → ws_h1`. Same dispatcher path
  as SS-over-QUIC. Cross-transport session resumption is preserved
  across the QUIC→WS pivot — the parked upstream re-attaches under the
  same VLESS Session ID.
- **UDP fallback chain:** `quic → ws_h2 → ws_h1`. Special-cased through
  `VlessUdpHybridMux`: the mux starts on QUIC and pivots to WS lazily
  when the first session's QUIC dial fails before any session has
  succeeded. Once any QUIC session has succeeded, runtime errors stay
  on QUIC (they reflect a real session failure, not an unreachable
  QUIC peer).
- **Resume:** TCP shares one `<uplink>#tcp` slot across QUIC and WS —
  the server parks both under the same `Parked::Tcp(Vless)` slot, so a
  single Session ID is valid through either carrier. UDP does not
  participate in resume (the hybrid mux re-creates per-target sessions
  on the WS side after the pivot).

## 5. VLESS over WebSocket (H3)

WebSocket carrier with VLESS framing. The VLESS server exposes a single
WS path (`ws_path_vless`) shared by TCP and UDP — VLESS UDP rides the
same WS session as TCP with mux.cool / XUDP framing.

```toml
[[outline.uplinks]]
name = "vless-ws-h3"
group = "main"
transport = "vless"
vless_ws_url = "wss://vless.example.com/SECRET/vless"
vless_mode = "h3"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 1.0
```

- **TCP fallback chain:** `ws_h3 → ws_h2 → ws_h1`. Inline
  `connect_websocket_with_resume` fallback, same as SS-over-WS.
- **UDP fallback chain:** `ws_h3 → ws_h2 → ws_h1`. UDP is multiplexed
  in the same WS session as TCP, so the carrier is shared and the
  downgrade marker propagates across both directions.
- **Resume:** one `<uplink>#tcp` slot covers TCP. UDP rides the same
  WS session, so it follows TCP's reconnects implicitly (no separate
  UDP resume token).

## 6. VLESS over XHTTP (H3)

`vless_mode = "xhttp_h3"` selects XHTTP packet-up over QUIC + HTTP/3.
The driver opens one long-lived GET (downlink) and pipelines POSTs
(uplink) sequenced by `X-Xhttp-Seq`. The base URL goes into
`vless_xhttp_url` (not `vless_ws_url`); the per-session id is appended
at dial time as one path segment after the base path. Useful when
WebSocket Upgrade is blocked on the network path (CDN gateways,
captive-portal middleboxes).

```toml
[[outline.uplinks]]
name = "vless-xhttp-h3"
group = "main"
transport = "vless"
vless_xhttp_url = "https://vless.example.com/SECRET/xhttp"
vless_mode = "xhttp_h3"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 1.0
```

- **TCP fallback chain:** `xhttp_h3 → xhttp_h2`. The dispatcher reuses
  the same `resume_request` token across the carrier switch, so a
  parked upstream re-attaches without producing a new VLESS session.
  There is no further fallback below `xhttp_h2` — XHTTP runs only on
  h2 / h3.
- **UDP fallback chain:** `xhttp_h3 → xhttp_h2`. XHTTP is a
  bidirectional packet-up driver on the same h2/h3 connection, so UDP
  rides alongside TCP in the same carrier and downgrades
  synchronously.
- **Resume:** the `<uplink>#tcp` slot is reused across the
  `xhttp_h3 → xhttp_h2` carrier switch — the same `resume_request`
  token is presented on either carrier, so the server re-attaches the
  parked upstream instead of opening a fresh session. UDP rides the
  same XHTTP carrier and inherits TCP's reconnect behaviour.

### Submode: packet-up vs stream-one

The wire submode is selected purely from the `?mode=` query string on
`vless_xhttp_url` — there is no separate config field. `XhttpSubmode`
is read on every dial, so flipping the URL is enough.

| URL                                              | Submode                |
|--------------------------------------------------|------------------------|
| `https://host/path/xhttp`                        | `packet-up` (default)  |
| `https://host/path/xhttp?mode=packet-up`         | `packet-up` (explicit) |
| `https://host/path/xhttp?mode=stream-one`        | `stream-one`           |
| `https://host/path/xhttp?mode=stream_one`        | `stream-one` (alias)   |

- **packet-up** (default) — one long-lived GET (downlink) plus a
  pipeline of POSTs (uplink) sequenced via `X-Xhttp-Seq`. Each uplink
  chunk is its own short request. Most tolerant to CDNs and
  middleboxes that buffer or close long-running POST bodies. Start
  here.
- **stream-one** — one bidirectional POST whose request body carries
  the uplink and response body carries the downlink. Less per-chunk
  overhead and lower small-packet latency. Requires `xhttp_h2` /
  `xhttp_h3` and a path that does not buffer POST bodies — proxies
  that wait for end-of-request before forwarding will stall the first
  byte. On h3 the `RequestStream` is split so uplink and downlink
  halves run on dedicated tasks.

Both submodes share the same `connect_xhttp` driver, so resume
behaviour, fallback chain (`xhttp_h3 → xhttp_h2`), and downgrade-window
mechanics are identical.

---

## Summary

| Configuration         | TCP chain                  | UDP chain                            | TCP resume        | UDP resume                |
|-----------------------|----------------------------|--------------------------------------|-------------------|---------------------------|
| Native SS             | none                       | none                                 | —                 | —                         |
| SS / WS / QUIC        | `quic → ws_h2 → ws_h1`     | `quic → ws_h2 → ws_h1`               | yes (`#tcp`)      | yes (`#udp`)              |
| SS / WS / H3          | `ws_h3 → ws_h2 → ws_h1`    | `ws_h3 → ws_h2 → ws_h1`              | yes (`#tcp`)      | yes (`#udp`)              |
| VLESS / QUIC          | `quic → ws_h2 → ws_h1`     | `quic → ws_h2 → ws_h1` (hybrid mux)  | yes (`#tcp`)      | no (sessions re-created)  |
| VLESS / WS / H3       | `ws_h3 → ws_h2 → ws_h1`    | `ws_h3 → ws_h2 → ws_h1`              | yes (`#tcp`)      | shared with TCP carrier   |
| VLESS / XHTTP / H3    | `xhttp_h3 → xhttp_h2`      | `xhttp_h3 → xhttp_h2`                | yes (`#tcp`)      | shared with TCP carrier   |

## Downgrade window mechanics

Recorded in two layers:

1. **Per-host `ws_mode_cache`** (short TTL). Set when an h3/h2 WS
   handshake fails. Subsequent dials to the same host clamp the
   requested mode down to the recorded ceiling. Survives across uplinks
   that share the same host.

2. **Per-uplink `mode_downgrade_until`**. Set when
   `note_advanced_mode_dial_failure` fires. `effective_tcp_mode` /
   `effective_udp_mode` return `WsH2` while the window is open, so
   probes, standby refills and direct dials all stop hammering the
   broken advanced mode. Cleared by a successful H3-recovery probe.

When both layers report the same constraint, `effective_*_mode` is
authoritative for routing and the host cache governs the inline
`connect_websocket_with_resume` clamp.

## Session resumption mechanics

`global_resume_cache` is a process-wide map keyed by
`<uplink_name>#tcp` / `<uplink_name>#udp`. The slot stores the last
Session ID the server issued for that uplink + direction.

On dial, the cached ID (if any) is presented to the server as a
`resume_request`:

- **WS path** — sent as the `X-Outline-Resume` request header alongside
  `X-Outline-Resume-Capable: 1`. The same token is reused if the dial
  falls back inline (h3 → h2 → h1).
- **VLESS-over-QUIC** — sent inside the VLESS Addons `SESSION_ID`
  opcode. The `#tcp` slot is shared with VLESS-over-WS, so a cached ID
  reattaches across either carrier.
- **XHTTP path** — sent as `X-Outline-Resume`; the same token is
  re-used across the `xhttp_h3 → xhttp_h2` carrier switch.

If the server replies with a `X-Outline-Session: <hex>` header (or the
VLESS equivalent in addons), the new ID is stored back into the slot
asynchronously, ready for the next reconnect.

UDP slots are separate so a TCP reconnect cannot pick up a UDP-side
Session ID by accident, and vice versa. Configurations where UDP rides
the TCP carrier (VLESS/WS, VLESS/XHTTP) do not maintain a separate
UDP slot — UDP follows TCP's lifetime.
