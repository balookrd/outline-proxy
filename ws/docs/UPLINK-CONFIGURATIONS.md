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
    `connect_transport` falls through to `ws_h1` inline.
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
  inside `connect_transport`. Each step is a fresh
  handshake on the same `tcp_ws_url`. Failure of `ws_h3` also records a
  host-level cap in `ws_mode_cache`, so subsequent dials within the
  cache TTL skip H3 even before the per-uplink downgrade window kicks
  in.
- **UDP fallback chain:** `ws_h3 → ws_h2 → ws_h1`. Same logic on the
  UDP-WS path.
- **Resume:** TCP and UDP each get their own slot in
  `global_resume_cache` (`<uplink>#tcp` / `<uplink>#udp`). Inline
  H3→H2→H1 fallback inside `connect_transport` carries the
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
  `connect_transport` fallback, same as SS-over-WS.
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

- **TCP fallback chain:** `xhttp_h3 → xhttp_h2 → xhttp_h1`. The
  dispatcher reuses the same `resume_request` token across each
  carrier switch, so a parked upstream re-attaches without producing
  a new VLESS session. The h1 carrier is the last-resort fallback
  for paths that block both QUIC and h2 ALPN; throughput is strictly
  worse (no multiplexing — see "h1 carrier shape" below) but the
  wire URL stays identical (`<base>/<session>/<seq>`) so the same
  `xhttp_path_vless` listener serves it.
- **UDP fallback chain:** `xhttp_h3 → xhttp_h2 → xhttp_h1`. XHTTP is
  a bidirectional packet-up driver on the same connection, so UDP
  rides alongside TCP in the same carrier and downgrades
  synchronously.
- **Resume:** the `<uplink>#tcp` slot is reused across every step of
  the `xhttp_h3 → xhttp_h2 → xhttp_h1` carrier switch — the same
  `resume_request` token is presented on each carrier, so the server
  re-attaches the parked upstream instead of opening a fresh session.
  UDP rides the same XHTTP carrier and inherits TCP's reconnect
  behaviour.

**h1 carrier shape.** Unlike h2 / h3, HTTP/1.1 cannot multiplex a
streaming GET against concurrent POSTs on a single connection, so the
h1 carrier dials **two** keep-alive sockets per session: one
dedicated to the long-lived downlink GET (chunked response body), and
one for strictly serialised uplink POSTs (one in-flight request at a
time). Pipelining is intentionally avoided — it is too brittle through
CDN / proxy intermediaries to rely on. As a result:

- Throughput is bounded by single-stream POST round-trip time; expect
  it to lag h2 noticeably under load.
- A single POST failure tears the uplink socket down and the driver
  exits, so the upstream sees a clean session drop rather than
  partial corruption. The next dial reattaches via the resume token.
- Stream-one submode is **not** carried on h1 — h1 cannot multiplex
  a streaming GET against a streaming POST on a single connection,
  so `?mode=stream-one` with `vless_mode = xhttp_h1` (or a chain that
  falls through to h1) is silently coerced to packet-up at dial time.
  The carrier shape switches to packet-up; the wire URL stays
  identical (`<base>/<session>/<seq>`). The defensive `packet-up only`
  bail in the inner h1 driver is preserved for direct callers that
  bypass the public `connect_xhttp` entry point.

## 7. VLESS share-link URIs

The five VLESS shapes above (sections 4–6, plus the `ws_h2` / `ws_h1`
variants of section 5) can also be configured through a single
`vless://UUID@HOST:PORT?...#NAME` URI — the share-link format used by
Xray / V2Ray clients. Set the `link` field instead of writing the
`vless_id` / `vless_*_url` / `vless_mode` triple by hand:

```toml
[[outline.uplinks]]
name = "vless-share"
group = "main"
link = "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fvless&alpn=h3&encryption=none#edge"
weight = 1.0
```

The loader expands the URI into the same internal fields the long-form
TOML produces, so the dial / fallback / resume behaviour is identical
to the corresponding section above. Setting `transport` is optional —
`link` implies `transport = "vless"`.

### Recognised query parameters

| URI element / param                | Maps to                                           |
|------------------------------------|---------------------------------------------------|
| `UUID` (userinfo)                  | `vless_id`                                        |
| `HOST:PORT` (authority)            | dial URL host + port (port is required)           |
| `type=ws`                          | `vless_mode = ws_h1` (with `alpn`: `ws_h2`/`ws_h3`), URL → `vless_ws_url` |
| `type=xhttp`                       | `vless_mode = xhttp_h2` (with `alpn=h3`: `xhttp_h3`; with `alpn=h1` / `http/1.1`: `xhttp_h1`), URL → `vless_xhttp_url` |
| `type=quic`                        | `vless_mode = quic`, URL → `vless_ws_url` (TLS-only) |
| `security=tls` / `reality`         | URL scheme → `wss://` (ws) or `https://` (xhttp/quic) |
| `security=none` (or absent)        | URL scheme → `ws://` / `http://`                  |
| `path=...`                         | URL path (percent-decoded; leading `/` added if missing) |
| `alpn=h3` / `h2` / `h1` / `h2,h3`  | picks the H1/H2/H3 mode variant; first token wins |
| `mode=packet-up` / `stream-one`    | propagated as `?mode=` on the XHTTP dial URL      |
| `encryption=none` (or absent)      | accepted (VLESS has no other encryption modes)    |
| `#NAME`                            | uplink name (percent-decoded)                     |

### Constraints and conflicts

- The URI must have an explicit `:port` — there is no scheme default.
- `link` is mutually exclusive with `vless_id`, `vless_ws_url`,
  `vless_xhttp_url` and `vless_mode`. Mixing them errors out at config
  load with a clear message; use the URI **or** the explicit fields.
- `flow=...` (xtls-rprx-vision) and `encryption=` other than `none`
  are rejected — no client-side implementation.
- `sni=` and `host=` parameters are only accepted when they match the
  authority host. The current transport stack reuses the URL host for
  both SNI and the HTTP `Host` header, so divergent values would be
  silently dropped — the loader fails fast instead.
- `type=tcp` / `type=grpc` / `type=h2` are rejected — the codebase
  has no carrier for them.
- Reality-specific parameters (`pbk`, `sid`, `spx`, `fp`) are accepted
  but have no effect; treat `security=reality` as a synonym for
  `security=tls` until reality lands.

The same `link` field is accepted by:

- The CLI flag `--vless-link <URI>` / `OUTLINE_VLESS_LINK` env var.
- The `/control/uplinks` REST endpoints, as `link` (alias `share_link`)
  inside the `uplink` JSON payload.

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
  halves run on dedicated tasks. On `xhttp_h1` the carrier silently
  uses packet-up (h1 has no equivalent shape).

Both submodes share the same `connect_xhttp` driver, so resume
behaviour, the h-version fallback chain
(`xhttp_h3 → xhttp_h2 → xhttp_h1`), and downgrade-window mechanics
are identical. The submode itself has its own one-step fallback —
see below.

#### `stream-one → packet-up` fallback

Stream-one's single long-lived POST is sensitive to middleboxes that
buffer or close streaming request bodies (CDNs, corporate proxies,
some mobile NATs). When the dial-time stream-one open fails on
`xhttp_h2` / `xhttp_h3`, the carrier retries packet-up on the **same**
TCP/TLS/h2 (or QUIC/h3) connection and records the failure in the
per-host XHTTP submode cache. Subsequent dials skip stream-one
upfront for `mode_downgrade_secs` and go straight to packet-up,
avoiding the doomed handshake on every connect. A successful
stream-one dial clears the block early.

The submode and h-version axes are independent: a stream-one block
on a host does not lower the h-version cap, and an h-version
downgrade does not refresh the stream-one block.

The dashboard surfaces the effective submode on the protocol pill —
configured `stream-one` displays as `/S`, packet-up adds no suffix,
and a live block renders as `/S↘P` to show the silent downgrade.
Snapshot fields:

- `tcp_xhttp_submode` / `udp_xhttp_submode` — submode parsed from
  the dial URL (`packet-up` / `stream-one`); `None` outside VLESS.
- `tcp_xhttp_submode_block_remaining_ms` /
  `udp_xhttp_submode_block_remaining_ms` — remaining TTL on the
  per-host stream-one block; `None` when the block has expired or
  was never set.

---

## Summary

| Configuration         | TCP chain                  | UDP chain                            | TCP resume        | UDP resume                |
|-----------------------|----------------------------|--------------------------------------|-------------------|---------------------------|
| Native SS             | none                       | none                                 | —                 | —                         |
| SS / WS / QUIC        | `quic → ws_h2 → ws_h1`     | `quic → ws_h2 → ws_h1`               | yes (`#tcp`)      | yes (`#udp`)              |
| SS / WS / H3          | `ws_h3 → ws_h2 → ws_h1`    | `ws_h3 → ws_h2 → ws_h1`              | yes (`#tcp`)      | yes (`#udp`)              |
| VLESS / QUIC          | `quic → ws_h2 → ws_h1`     | `quic → ws_h2 → ws_h1` (hybrid mux)  | yes (`#tcp`)      | no (sessions re-created)  |
| VLESS / WS / H3       | `ws_h3 → ws_h2 → ws_h1`    | `ws_h3 → ws_h2 → ws_h1`              | yes (`#tcp`)      | shared with TCP carrier   |
| VLESS / XHTTP / H3    | `xhttp_h3 → xhttp_h2→ xhttp_h1` | `xhttp_h3 → xhttp_h2 → xhttp_h1` | yes (`#tcp`) | shared with TCP carrier   |

## Top-level `[outline]` shape

The `[outline]` table groups everything that drives the proxying engine —
transports, uplinks, probing, load balancing — separately from host-level
concerns (`[socks5]`, `[metrics]`, `[control]`, `[dashboard]`,
`[tcp_timeouts]`, `[tun]`, `[[route]]`). Two configuration shapes are
supported.

**1. Inline single-uplink shorthand.** Writing `transport`, `tcp_ws_url`,
`udp_ws_url`, `vless_ws_url`, `vless_xhttp_url`, `tcp_mode` / `udp_mode` /
`vless_mode`, `link`, `tcp_addr`, `udp_addr`, `method`, `password`,
`fwmark`, `ipv6_first` directly under `[outline]` (or — for backward
compatibility — at the top level) declares a single implicit uplink. CLI
flags (`--tcp-ws-url`, `--password`, …) target this shape. Convenient for
trivial deployments; not used together with `[[outline.uplinks]]` /
`[[uplink_group]]`.

```toml
[outline]
transport = "ws"                  # "ws" (default; alias "websocket") | "shadowsocks" | "vless"
tcp_ws_url = "wss://example.com/SECRET/tcp"
udp_ws_url = "wss://example.com/SECRET/udp"
tcp_mode = "h3"
udp_mode = "h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"
```

`outline.transport` accepts:

| value         | wire shape                                                                       |
|---------------|----------------------------------------------------------------------------------|
| `ws`          | Shadowsocks AEAD framing inside a WebSocket carrier (default; alias `websocket`) |
| `shadowsocks` | Plain Shadowsocks over raw TCP/UDP sockets — see § 1                             |
| `vless`       | VLESS over WebSocket or XHTTP (h1/h2/h3) — see §§ 4–7                            |

**2. Multi-uplink + groups (production shape).** `[[outline.uplinks]]`
declares uplinks; `[[uplink_group]]` (top-level, *not* nested under
`[outline]`) declares groups; each uplink names its group via
`group = "..."`. In this shape every uplink carries its own `transport`
field, so the inline `outline.transport` is unused.

## Load-balancing reference

Two equivalent surfaces, picked by config shape:

- **`[outline.load_balancing]`** — applies in inline single-uplink
  shorthand (no `[[uplink_group]]` declared). Folded into the implicit
  default group at load time
  ([groups.rs:21](src/config/load/groups.rs:21)).
- **Fields directly under `[[uplink_group]]`** — apply per group when
  `[[uplink_group]]` is in use (the `[outline.load_balancing]` block is
  silently ignored in this shape;
  [groups.rs:171](src/config/load/groups.rs:171)).

Field names and defaults are identical between the two surfaces. All
fields are optional; omitted fields fall back to the defaults below.

| field                                | default            | unit  | purpose                                                                                           |
|--------------------------------------|--------------------|-------|---------------------------------------------------------------------------------------------------|
| `mode`                               | `"active_active"`  | enum  | `active_active` spreads per-flow / per-uplink load; `active_passive` keeps one active, others as failover |
| `routing_scope`                      | `"per_flow"`       | enum  | `per_flow` (per-session selection) / `per_uplink` (sticky by host:port) / `global` (single active for the whole instance) |
| `sticky_ttl_secs`                    | `300`              | s     | how long a `(host, port)` keeps its assigned uplink                                               |
| `hysteresis_ms`                      | `50`               | ms    | minimum gap between two `active` switches; suppresses flapping                                    |
| `failure_cooldown_secs`              | `10`               | s     | how long after a failure the uplink is excluded from selection                                    |
| `tcp_chunk0_failover_timeout_secs`   | `10`               | s     | wait for the first response byte from origin before failing over to the next uplink               |
| `auto_failback`                      | `false`            | bool  | return to the originally-preferred uplink once it recovers                                        |
| `warm_standby_tcp`                   | `0`                | int   | pre-warmed TCP connections to keep on standby uplinks                                             |
| `warm_standby_udp`                   | `0`                | int   | same for UDP                                                                                      |
| `warm_probe_keepalive_secs`          | `20`               | s     | keepalive cadence for cached warm-probe pipes (`0` disables)                                      |
| `rtt_ewma_alpha`                     | `0.3`              | (0,1] | smoothing factor for the per-uplink RTT EWMA used in selection scoring                            |
| `failure_penalty_ms`                 | `500`              | ms    | initial RTT penalty added on a fresh runtime failure                                              |
| `failure_penalty_max_ms`             | `30000`            | ms    | cap on the cumulative failure penalty                                                             |
| `failure_penalty_halflife_secs`      | `60`               | s     | half-life of the failure-penalty exponential decay                                                |
| `runtime_failure_window_secs`        | `60`               | s     | window over which back-to-back data-plane failures stack toward a health flip; `0` = legacy (no decay) |
| `mode_downgrade_secs`                | `60`               | s     | cooldown before retrying the configured advanced mode (H3 / QUIC / `xhttp_h{2,3}`) after fallback. Legacy alias: `h3_downgrade_secs` |
| `global_udp_strict_health`           | `false`            | bool  | in `routing_scope = "global"`, also gate the active uplink on UDP health; default lenient — UDP failures are informational |
| `udp_ws_keepalive_secs`              | `60`               | s     | WS Ping cadence on idle UDP-WS sockets (`0` disables)                                             |
| `tcp_ws_keepalive_secs`              | `60`               | s     | WS Ping cadence on idle VLESS-over-WS TCP sessions (`0` disables; SS-over-WS ignores)             |
| `tcp_ws_standby_keepalive_secs`      | `20`               | s     | WS Ping cadence on warm-standby TCP sockets (`0` disables)                                        |
| `tcp_active_keepalive_secs`          | `20`               | s     | SS2022 0-length keepalive on active SOCKS TCP sessions (`0` disables; SS1 ignores)                |
| `tcp_mid_session_retry_buffer_bytes` | `262144`           | bytes | per-session ring-buffer cap for the Ack-Prefix mid-session retry path (`0` disables retry; see "Mid-session retry" below) |
| `tcp_mid_session_retry_budget`       | `1`                | int   | maximum number of mid-session redial attempts per session (`0` disables retry — equivalent to `tcp_mid_session_retry_buffer_bytes = 0`) |
| `tcp_mid_session_retry_overflow_policy` | `"soft"`        | enum  | behaviour on a chunk larger than the retry buffer cap: `"soft"` (default) keeps the session alive and surfaces `failed_replay` on future retries; `"hard"` drops the session immediately to guarantee retryability for the rest |
| `tcp_mid_session_retry_consume_timeout_secs` | `5`            | s     | hard upper bound on how long the orchestrator waits for the v1 Ack-Prefix control frame on a successful resume hit; bounds a misbehaving server from stalling the pinned relay invisibly |
| `tcp_symmetric_replay_enabled`       | `true`             | bool  | opt into the v2 Symmetric Downlink Replay protocol on retry redials; flip to `false` to suppress the v2 advertise without disabling v1.x retry (e.g. while staging the server-side rollout) |
| `tcp_symmetric_replay_max_bytes`     | `1048576`          | bytes | hard cap on accepted v2 `replay_len` from the server; replies above this drop the session — protection against a hostile peer forcing unbounded buffering |
| `vless_udp_max_sessions`             | `256`              | int   | hard cap on concurrent VLESS UDP sessions (LRU-evicted on overflow)                               |
| `vless_udp_session_idle_secs`        | `60`               | s     | evict VLESS UDP sessions idle longer than this (`0` disables eviction)                            |
| `vless_udp_janitor_interval_secs`    | `15`               | s     | how often the VLESS UDP janitor scans for idle sessions                                           |

Source of defaults:
[`src/config/load/balancing.rs`](src/config/load/balancing.rs); the
`vless_udp_*` fallback comes from
[`crates/outline-transport/src/vless/udp_mux.rs`](crates/outline-transport/src/vless/udp_mux.rs).

Routing-scope cheat sheet:

- **`per_flow`** — recommended default. Each new SOCKS/TUN session picks
  an uplink based on weight, RTT EWMA and current penalties; existing
  sessions stay on their uplink for the whole flow. Best parallelism,
  smallest blast radius.
- **`per_uplink`** — assigns flows that share a `(host, port)` to the
  same uplink for `sticky_ttl_secs`. Useful when an origin is sensitive
  to source-IP churn (anti-fraud, sticky session cookies bound to
  client IP).
- **`global`** — exactly one uplink is `active` instance-wide; failover
  is gated by `hysteresis_ms` + `failure_cooldown_secs`. Use for clean
  dashboard semantics on devices that should look like they have a
  single egress (routers, single-purpose home-gateway).

Mode-vs-scope interaction:

- `active_active` + `per_flow` is the only combination that exercises
  weighted load distribution.
- `active_passive` + `global` mirrors the classic primary/backup
  pattern — one uplink carries everything, others wait.
- `active_passive` + `per_flow` is legal but has reduced meaning:
  passive uplinks act only as failover targets, not weighted siblings.

Strict reselection in `active_passive`:

Whenever the active uplink changes (probe-driven failover, manual
control-plane switch, `auto_failback` decision) the proxy enforces
egress consistency by tearing down sessions that are still pinned to
the now-passive uplink — different uplinks usually have different
egress IPs and leaving an inflight session on the stale uplink would
break source-IP-bound state on the destination side.

- **SOCKS5 TCP**: the pinned-relay watcher observes the active-uplink
  switch and forcibly closes the SOCKS5 client socket with TCP RST
  (`SO_LINGER {l_onoff=1, l_linger=0}` + drop). The client
  application sees a hard reset on its TCP and reconnects through the
  new active uplink. Counted on
  `outline_ws_rust_socks_tcp_strict_aborts_total{reason="global_switch"}`.
- **SOCKS5 UDP**: the per-group downlink loop subscribes to the same
  signal and atomically replaces the transport on switch
  (`reconcile_global_udp_transport`); the client never sees an L4
  close (UDP has no analogue) but the next datagram already uses the
  new uplink.
- **TUN TCP**: mirrors the SOCKS5 behaviour but at L3 — the TUN
  engine emits a `RST+ACK` segment to the in-kernel TCP of the client
  app. See `outline_ws_rust_tun_tcp_events_total{event="global_switch"}`.

The behaviour is opt-in by virtue of running in `active_passive` (any
scope); `active_active` is unaffected — the strict-abort watcher
never fires there because there is no single "active" uplink to
diverge from. Operators who want session-by-session migration without
the abort should stay on `active_active` + `per_flow`.

Mid-session retry (Ack-Prefix Protocol v1):

- When a pinned SOCKS TCP session loses its upstream transport
  mid-stream (H3 APPLICATION_CLOSE, NAT eviction, server-initiated
  reset, etc.), the relay can opt into a one-shot transparent
  re-dial against the same SS-WS uplink. The new dial advertises
  `X-Outline-Resume-Ack-Prefix: 1`; an outline-ss-rust server with
  the feature emits a 14-byte control frame on resume hit reporting
  the exact upstream byte offset it has acked. The client replays
  the buffered uplink tail from that offset so the upstream sees
  every byte exactly once.
- `tcp_mid_session_retry_buffer_bytes` sets the per-session ring-
  buffer cap. Default `262144` (256 KiB) — large enough to absorb
  most HTTP request bodies and idempotent RPC payloads, small enough
  that holding it for N concurrent sessions stays negligible
  compared with kernel socket buffers. Set to `0` to disable retry
  entirely (the buffer is never allocated).
- `tcp_mid_session_retry_budget` caps the number of redial attempts
  per session. Default `1` — most retriable mid-session failures
  recover on the first attempt. Higher values pay off only against
  genuinely-flaky transports; each attempt costs one full buffer
  replay even on persistent failure. `0` disables retry entirely
  (same effect as setting the buffer cap to `0`).
- `tcp_mid_session_retry_overflow_policy` decides what happens when
  a single uplink chunk is larger than
  `tcp_mid_session_retry_buffer_bytes`. The chunk on its own cannot
  be replayed, so the session's retry-correctness contract is
  irrecoverably broken from this point. `"soft"` (default) fires the
  `outcome="buffer_overflow"` metric, sends the chunk through anyway,
  and continues — future retries on this session will surface
  `failed_replay`. `"hard"` drops the session immediately. Pick
  `"hard"` when retry-correctness for the whole deployment matters
  more than keeping one outlier session alive (e.g. interactive
  RPCs where a torn replay would corrupt state); pick `"soft"`
  (the default) for general-purpose web traffic where session
  liveness is the user-visible metric.
- `tcp_mid_session_retry_consume_timeout_secs` bounds how long the
  orchestrator waits for the server to emit the v1 Ack-Prefix
  control frame on a successful resume hit. The server's emit
  happens immediately on resume; the timeout exists to fail fast
  when the path is broken or the server is misbehaving. Default `5`
  comfortably absorbs satellite + cellular latencies. Tighten on
  known-low-RTT deployments; significantly larger values usually
  mask retry behaviour problems.
- v1 sweet spot: HTTP request bodies, idempotent RPCs. NOT for
  SSH-style downlink-heavy sessions on its own — v1 does not
  replay the downlink direction. The v2 Symmetric Downlink Replay
  protocol (see below) closes that gap.
- Gated to WS-family carriers — SS-WS (`transport = "ws"`) and
  VLESS-WS (`transport = "vless"`). Raw QUIC and direct-socket
  Shadowsocks are no-ops for retry in v1; the relay falls back to
  the legacy "single shot, propagate error" behaviour with no
  observable change.
- The redial dials the **wire the manager currently considers
  active** for this transport (`active_wire`), not unconditionally
  the primary. When an earlier primary failure has advanced
  `active_wire` to a fallback, the retry dials that fallback with
  the same Ack-Prefix / Symmetric Downlink Replay capability the
  primary path uses, instead of slamming the dead primary URL and
  inflating the parent uplink's runtime-failure streak. The
  fallback wire must itself be SS-WS or VLESS-WS for the retry to
  apply; an SS-direct or raw-QUIC fallback collapses the retry to a
  no-op and the session ends on the original mid-stream error.
- Outcomes are exposed on
  `outline_ws_rust_uplink_mid_session_retries_total{outcome}` with
  `outcome ∈ {success, failed_redial, failed_replay,
  buffer_overflow, downlink_truncated}`. See
  `docs/SESSION-RESUMPTION.md` § Ack-Prefix Protocol (v1) in the
  outline-ss-rust repo for the wire format.

Symmetric Downlink Replay (v2):

- Optional opt-in extension on top of v1.x. Closes the
  byte-loss gap in the **downstream** direction (server→client)
  that v1 leaves open: bytes the server emitted to the WebSocket
  but the client never observed before the carrier TCP died are
  replayed on the next resume hit, in order, BEFORE any fresh
  upstream traffic flows. Required for SSH and other protocols
  that treat the byte stream as a single ordered log; an
  application-layer-retried protocol (HTTP request bodies,
  idempotent RPCs) can leave this off and rely on v1 only.
- Wire side: client advertises
  `X-Outline-Resume-Symmetric-Replay: 1` AND reports its current
  `client_acked_offset` via `X-Outline-Resume-Down-Acked: <decimal>`.
  Server emits a 14-byte `"ORDR"` control frame + replay payload
  (bytes `[client_acked_offset, total_sent_downlink)`) immediately
  after the v1 `"ORSM"` frame on the resume hit. Server gates v2
  on (a) v1 also being negotiated and (b) its
  `[session_resumption].downlink_buffer_bytes > 0` config knob
  (default `0` = disabled). Full spec lives in the server repo's
  `docs/SESSION-RESUMPTION.md` § Symmetric Downlink Replay (v2).
- `tcp_symmetric_replay_enabled` (default `true`) — operator
  switch. The capability is engaged at runtime only when (a)
  v1.x retry is enabled (`tcp_mid_session_retry_buffer_bytes > 0`
  AND `tcp_mid_session_retry_budget > 0`), (b) this knob is on,
  AND (c) the server echoes both v1 and v2 capabilities. Setting
  to `false` suppresses the v2 advertise without touching v1.x.
- `tcp_symmetric_replay_max_bytes` (default `1048576` = 1 MiB) —
  hard cap on the v2 `replay_len` the client will accept. Server
  replies above this drop the session per spec; protects against
  a hostile peer forcing unbounded buffering. Servers in a sane
  deployment configure `downlink_buffer_bytes` well below this
  cap (default 64 KiB on the server side), so this fires only on
  a genuinely misbehaving peer.
- Truncation policy: when the server signals
  `REPLAY_TRUNCATED` (its ring rolled past the client-reported
  offset, e.g. very long park or very small server buffer), the
  client respects `tcp_mid_session_retry_overflow_policy`:
  `"soft"` continues the session under an irrecoverable
  downstream gap and increments
  `outline_ws_rust_uplink_mid_session_retries_total{outcome="downlink_truncated"}`;
  `"hard"` drops the session immediately. Use the same value as
  for the v1 buffer-overflow case to keep policy consistent.
- Same eligibility gate as v1 — SS-WS / VLESS-WS / VLESS-XHTTP
  carriers; raw QUIC and direct-socket Shadowsocks are out of
  scope (no HTTP-layer carrier for the v2 negotiation).

Example — `[outline.load_balancing]` for the inline shape, and the same
fields lifted onto a group:

```toml
# Inline single-uplink shorthand
[outline.load_balancing]
mode = "active_active"
routing_scope = "per_flow"
sticky_ttl_secs = 300
hysteresis_ms = 50
failure_cooldown_secs = 10
warm_standby_tcp = 1
warm_standby_udp = 1
rtt_ewma_alpha = 0.3
failure_penalty_ms = 500
failure_penalty_max_ms = 30000
failure_penalty_halflife_secs = 60
mode_downgrade_secs = 60
runtime_failure_window_secs = 60
global_udp_strict_health = false
auto_failback = false

# Equivalent for multi-group shape — same field names directly on the group:
[[uplink_group]]
name = "main"
mode = "active_active"
routing_scope = "per_flow"
sticky_ttl_secs = 300
hysteresis_ms = 50
warm_standby_tcp = 1
# … etc.
```

## Per-group probe overrides

`[outline.probe]` is a template inherited by every `[[uplink_group]]`.
Individual groups can override probe parameters via `[uplink_group.probe]`,
which is bound to the **most recently declared** `[[uplink_group]]` table —
place the override block immediately after the group it should apply to and
before the next `[[uplink_group]]`.

Merge rules:

- **Scalar fields** (`interval_secs`, `timeout_secs`, `max_concurrent`,
  `max_dials`, `min_failures`, `attempts`) are merged field-by-field with
  the template — fields not set in the override fall back to
  `[outline.probe]`.
- **Sub-tables** (`ws` / `http` / `dns` / `tcp` / `tls`) are replaced
  wholesale. If a group sets `[uplink_group.probe.http]`, the template's
  `[outline.probe.http]` is dropped for that group — repeat every field
  you still want.
- **Activation requires at least one of `ws` / `http` / `dns` / `tcp` /
  `tls`** in the resulting (post-merge) probe config; otherwise the
  probe loop will not start for that group.
- **Application-level sub-probes are mutually exclusive.** Only one of
  `tls` / `http` / `tcp` runs per cycle to bound the per-cycle handshake
  count. Priority is `tls` → `http` → `tcp`: when `[outline.probe.tls]`
  is set, the `http` and `tcp` sub-tables are silently skipped each
  cycle. `ws` and `dns` always run alongside whichever of the three is
  active.

Example — the `backup` group probes less aggressively, swaps the HTTP
target, and reuses the template's WS / DNS sub-tables:

```toml
[outline.probe]
interval_secs  = 30
timeout_secs   = 10
max_concurrent = 4
max_dials      = 2

[outline.probe.ws]
enabled = true

[outline.probe.http]
url = "http://example.com/"

[outline.probe.dns]
server = "1.1.1.1"
port   = 53
name   = "example.com"


[[uplink_group]]
name = "main"
mode = "active_active"
# … inherits [outline.probe] verbatim …


[[uplink_group]]
name = "backup"
mode = "active_passive"
routing_scope = "global"

# Override applies to "backup" (the most recent [[uplink_group]] above):
[uplink_group.probe]
interval_secs = 60   # poll the fallback path less often
min_failures  = 2    # tolerate a single transient blip

# Replaces [outline.probe.http] entirely for this group:
[uplink_group.probe.http]
url = "http://backup-canary.example.net/"

# [uplink_group.probe.ws] / .dns are not overridden, so the group inherits
# the template's `ws` and `dns` sub-tables unchanged.
```

**Disabling a probe type in a single group:**

- `ws`: set `[uplink_group.probe.ws] enabled = false` in the override —
  `WsProbeConfig` carries an explicit `enabled` flag.
- `http` / `dns` / `tcp` / `tls`: cannot be disabled per group. The merge
  uses `override.or(template)` ([groups.rs:160](src/config/load/groups.rs:160)),
  so an omitted sub-table inherits the template's value, and there is no
  syntax for "explicit none". To run a group without one of these probes
  while another group keeps it, remove the sub-table from
  `[outline.probe]` and re-declare it only inside the groups that need
  it via `[uplink_group.probe.<kind>]`.

## TLS handshake-only data-path probe (`[outline.probe.tls]`)

The plain HTTP probe drives a `HEAD` request through the tunnel against
a configured `http://...` URL — it never exercises TLS, so an upstream
filter that silently drops `ServerHello` records for specific SNIs is
invisible to it. The user-flow `chunk0_timeout` failure mode (handshake
to the uplink server succeeds, ClientHello is forwarded to the upstream
target, no response bytes ever come back) therefore goes unnoticed:
`uplink_health` stays `1`, the streak that would flip it never reaches
`probe.min_failures`, and per-flow rescue keeps absorbing the symptom.

`[outline.probe.tls]` closes that gap. It opens the same tunnel as the
HTTP probe and then drives a real `ClientHello → ServerHello /
Certificate → Finished → close_notify` handshake against a configured
`(SNI, port)` target. No HTTP exchange follows — the goal is to
reproduce the chunk-0 wait-for-server-bytes shape exactly, so the
probe fails on the same conditions user flows do and the runtime
escalation path (`probe-driven healthy=false → uplink dropped from
selection → global active slides off`) actually fires.

```toml
[outline.probe.tls]
# Each target is one of:
#   - full URL:           "https://www.youtube.com/"
#   - URL with port:      "https://www.youtube.com:8443/"
#   - bare host:port:     "www.youtube.com:443"
#   - bare host:          "www.instagram.com"     # → port 443
#   - bracketed IPv6:     "[::1]:8443"
# The URL form accepts only `https://` (TLS-handshake-only probe makes
# no sense over `http://`). Path/query/fragment are ignored — this probe
# never sends an HTTP request, only a TLS handshake.
# The probe rotates one entry per cycle so per-SNI filtering surfaces
# instead of being masked by one always-reachable target.
targets = [
  "https://www.youtube.com/",
  "www.instagram.com",
]
```

Choosing targets:

- Pick SNIs the deployment's user traffic actually hits, not stub
  origins like `example.com`. The probe is only useful when its target
  is sensitive to the same upstream filter the user flows are.
- Two to four targets is plenty. Probes pay one fresh handshake per
  uplink per cycle, and rotation across the list spreads cycle load.
- Skip self-hosted SNIs (your own uplink server's WS host) — the WS
  sub-probe already covers that path.

Metrics emit `probe="tls"`. Split it out from `probe="http"` /
`probe="ws"` on the dashboard's "Probe Runs (success/error, by
sub-probe)" panel to see the new signal independently. In a TLS-DPI
episode the `probe="tls" result="error"` series should track the
user-flow `runtime_failure_signatures_total{signature="chunk0_timeout"}`
shape; if it stays flat while user flows pile up, the chosen targets
are not under the same filter and need rotating.

Mutually exclusive with `[outline.probe.http]` and `[outline.probe.tcp]`
inside one cycle (priority: `tls` → `http` → `tcp`). It is fine to
leave a `[outline.probe.http]` block in the template for groups that
do not declare `tls` — the cycle picks the highest-priority block that
is set.

## Downgrade window mechanics

Recorded in two layers:

1. **Per-host caches** (short TTL, one per axis).
   - `ws_mode_cache` — set when an h3/h2 WS handshake fails. Caps
     subsequent dials to the same host at the recorded ceiling
     (`WsH2` after a `WsH3` failure, `WsH1` after a `WsH2` failure).
   - `xhttp_mode_cache` — sibling cache for the XHTTP h-version
     chain. Set when an `xhttp_h3` or `xhttp_h2` dial fails; caps
     subsequent dials at `XhttpH2` / `XhttpH1` respectively.
     Independent from the WS cache so a `record_failure` on one
     chain cannot clobber the other's cap when several uplinks
     share a `(host, port)` but use different transports.
   - `xhttp_submode_cache` — orthogonal axis: tracks per-host
     stream-one failures. Set when a `?mode=stream-one` dial fails
     on `xhttp_h2` / `xhttp_h3`; clamps subsequent submode
     selections to `packet-up` for the TTL window. Independent from
     the h-version cache so a stream-one failure does not refresh
     the h-version cap and vice versa.

   All three caches are keyed by **destination** `host:port` (the
   dial URL, not the local interface), so they survive across
   uplinks pointing at the same upstream and across changes in the
   local route / `fwmark`. The shared `mode_downgrade_secs` knob
   governs the TTL for all three.

2. **Per-uplink `mode_downgrade_until`** + family-aware
   `mode_downgrade_capped_to`. Set when `note_advanced_mode_dial_failure`
   or `note_silent_transport_fallback` fires. `effective_tcp_mode` /
   `effective_udp_mode` return the cap (not the configured mode) while
   the window is open, so probes, standby refills and direct dials all
   stop hammering the broken advanced mode. Family-aware: `WsH3` /
   `Quic` collapse to `WsH2`, `XhttpH3` collapses to `XhttpH2`,
   `XhttpH2` to `XhttpH1`. Multi-step XHTTP downgrades
   (`XhttpH3 → XhttpH2 → XhttpH1`) converge over consecutive dials —
   each silent-fallback observation lowers the cap one rank inside the
   active window and never raises it. Cleared by a successful H3
   recovery probe (WS path) or by natural TTL expiry (XHTTP path —
   no recovery probe). The cap is published through the snapshot
   (`tcp_mode_capped_to` / `udp_mode_capped_to`) so the dashboard's
   `tcp_mode_effective` / `udp_mode_effective` columns reflect the
   actual carrier the dispatcher will use.

When both layers report the same constraint, `effective_*_mode` is
authoritative for routing and the host cache governs the inline
`connect_transport` clamp.

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
  re-used across every step of the
  `xhttp_h3 → xhttp_h2 → xhttp_h1` carrier switch.

If the server replies with a `X-Outline-Session: <hex>` header (or the
VLESS equivalent in addons), the new ID is stored back into the slot
asynchronously, ready for the next reconnect.

UDP slots are separate so a TCP reconnect cannot pick up a UDP-side
Session ID by accident, and vice versa. Configurations where UDP rides
the TCP carrier (VLESS/WS, VLESS/XHTTP) do not maintain a separate
UDP slot — UDP follows TCP's lifetime.

## Browser fingerprint diversification

WS / XHTTP dials can mix in browser-style identification headers
(`User-Agent`, `Accept-*`, Sec-CH-UA family, Sec-Fetch-*) so a passive
DPI rule keying on "WS upgrade missing User-Agent" stops separating
this client from real browser traffic. The pool ships six profiles:
Chrome 142 (Windows + macOS), Firefox 150 (Windows + macOS),
Safari 19 (macOS), Edge 142 (Windows).

Two stable strategies are offered. **`process_stable` (the
recommended default)** picks one identity at process start and uses
it for every dial regardless of which uplink fires — matching how a
real user with a single browser appears to an on-path observer:
one source IP, one User-Agent. The pick is seeded from the OS-level
hostname (`gethostname(2)` on Unix, `%COMPUTERNAME%` from the
process environment on Windows), so identity stays stable across
restarts on the same machine. In containers / sandboxes started
without an explicit hostname (`docker run --hostname=""`,
`unshare --uts /bin/sh -c …` and friends), the syscall returns no
useful value and the seed falls back to a fresh `rand` pick at
process start — still stable for the duration of the process,
rotates on restart. Operators who want a deterministic identity in
a container should pass `--hostname` (Docker), `Hostname=` (systemd)
or the equivalent runtime knob; reading the shell variable
`$HOSTNAME` will *not* work because daemons don't inherit it.

`per_host_stable` is the legacy peer-split: profile is hashed from
`(host, port)`, so each peer sees one consistent identity but
**different** peers see different identities from the same source
IP. Useful only when peers are fully decoupled across observers
(different ASes, different jurisdictions, no global DPI on the
client's path). For most deployments this leaks "automated
multi-pseudo-client" because a global observer correlates: the
same source IP shouldn't produce four browser identities in 30
seconds against four different hosts. Prefer `process_stable`
unless you have a specific reason.

The knob is opt-in. Default behaviour leaves the wire shape exactly
as in pre-fingerprint builds — no headers added beyond
`X-Outline-Resume-*`. Enable it via the top-level `fingerprint_profile`
key in `config.toml`:

```toml
# top-level — sibling of [socks5], [metrics], [outline], [[uplink_group]]
fingerprint_profile = "stable"   # alias for `process_stable` — recommended
```

Accepted values:

- `"off"` / `"none"` / `"disabled"` / omitted — default, no headers added.
- `"stable"` / `"process"` / `"process_stable"` / `"process-stable"` —
  **recommended.** One identity for the entire process; a real-user
  shape on the wire from the perspective of any observer.
- `"per_host_stable"` / `"per-host-stable"` / `"per-host"` — legacy
  per-peer split; see caveat above.
- `"random"` — fresh profile on every dial. Useful for testing or
  when peer-stable identity is itself undesirable.

> Note: the bare `stable` shorthand previously aliased to
> `per_host_stable`. It now resolves to `process_stable`. Operators
> carrying older configs spelling `stable` get the safer behaviour
> automatically; those who specifically want the per-peer split
> must spell `per_host_stable` in full.

The same value can be set on the command line or via environment,
which **overrides** the top-level TOML key (per-uplink overrides
still win on top of either source — same precedence as
`--listen` / `--metrics-listen`):

```sh
outline-ws-rust --fingerprint-profile stable
# or:
OUTLINE_FINGERPRINT_PROFILE=random outline-ws-rust
```

Accepts the same alias set as the TOML key. Useful for one-shot
opt-in tests against a deployed config without editing the file.

For embedded callers (tests, custom binaries) the strategy can also be
wired directly via the Rust API; the bootstrap binary picks the
config value at startup:

```rust
use outline_transport::{
    init_fingerprint_profile_strategy, FingerprintProfileStrategy,
};

init_fingerprint_profile_strategy(FingerprintProfileStrategy::ProcessStable);
```

### Observability

`tracing::info!` logs each `(host, port, profile)` triple the first
time it is observed in the process — useful for verifying that the
strategy actually engaged after a config change.

Prometheus exposes `outline_ws_rust_uplink_fingerprint_profile_strategy_info`
with labels `group`, `uplink`, and `strategy` (one of `none`,
`per_host_stable`, `process_stable`, `random`). The gauge is `1` on the active strategy
and `0` on the others, published unconditionally — an absent series
points at a snapshot-pipeline bug, not at the feature being off.
The series reflects the **effective** strategy: per-uplink override
when set, otherwise the process-wide default. The same string is
available on the `/snapshot` control endpoint as the
`fingerprint_profile_strategy` field on each uplink entry — the field
is omitted from the JSON when the strategy resolves to `none`, so
older snapshot consumers see the same wire shape they had before
this knob landed.

The bundled Grafana dashboard ships a stat panel **"Fingerprint
Strategy"** in the top-status row alongside `Selection Mode`,
`Routing Scope`, and `Active Uplink`. Each cell shows how many uplinks
in the selected `group` filter currently sit on each strategy bucket;
zero buckets stay greyed-out so the active distribution reads at a
glance.

The bundled HTML control-plane dashboard renders a per-uplink chip
showing the **active profile** (e.g. `Chrome 142 macOS`) next to the
protocol pill on every row where the effective strategy resolves to
something other than `none`. The chip is colour-coded by family:
blue for the stable profiles (Chrome / Firefox / Safari / Edge under
`process_stable` or `per_host_stable`) and purple for `Random` —
at-a-glance the operator can tell whether the identity is pinned or
rolling. Uplinks on `none` get no chip — the common opt-out
deployment stays visually unchanged. The tooltip carries both the
raw profile id and the strategy
(`fingerprint_profile_name = chrome-142-macos · strategy = process_stable`)
so the rendered label can be correlated immediately with the
Prometheus `strategy` label and the snapshot JSON without translating
between forms.

The active profile is computed in the snapshot builder by running
`select_with_strategy(primary_dial_url, effective_strategy)` —
`tcp_dial_url()` first, falling back to `udp_dial_url()` for
UDP-only uplinks, and skipped entirely for plain Shadowsocks
uplinks (no URL → no profile). Surfaced as
`UplinkSnapshot::fingerprint_profile_name` and forwarded through
the topology JSON as `fingerprint_profile_name` (omitted when
absent).

### Per-uplink override

Each `[[outline.uplinks]]` entry can override the top-level value with
its own `fingerprint_profile` key. Useful when one uplink must keep a
byte-identical xray-style wire shape while siblings on the same host
opt into per-host-stable identities:

```toml
fingerprint_profile = "stable"  # default for all uplinks below

[[outline.uplinks]]
name = "cdn-fronted"
group = "main"
tcp_ws_url = "wss://cdn.example.com/secret/tcp"
# inherits "stable" from the top-level

[[outline.uplinks]]
name = "xray-shaped"
group = "main"
tcp_ws_url = "wss://xray.example.com/secret/tcp"
fingerprint_profile = "off"      # explicit opt-out for byte-identity
```

The override propagates through a per-dial task-local scope inside
`outline-uplink::dial::dial_in_uplink_scope`, so probes, warm-standby
refills, and live dispatches all honour the same value for a given
uplink. The scope drops when the dial future returns; spawned
post-handshake tasks (drivers, body-drain loops) inherit nothing —
which is fine because the only `select` call lives at the dial
entry-point.

What this does **not** cover (separate, costlier work):

- TLS ClientHello / JA3 / JA4 fingerprint — rustls does not expose
  cipher / extension / curve order, so meaningful diversification
  here needs a uTLS-style stack (e.g. `boring`/BoringSSL).
- ALPN ordering — currently fixed per carrier (`h2`, `http/1.1`,
  `h3`, `vless`, `ss`). The TLS configs are cached per ALPN list,
  so per-host ALPN reshuffling needs a new caching key.
- HTTP/2 `SETTINGS` frame fingerprint (Akamai/JA4H2) — owned by
  the `h2` crate and largely closed to client-side tweaks.
- QUIC transport-parameter ordering — owned by `quinn`.

## Per-uplink fallback transports

A single `[[outline.uplinks]]` entry can carry an ordered list of
**fallback transports** that the dial loop tries when the primary
transport on this uplink fails to dial. The motivating use-case is a
VLESS endpoint that gets blocked at the network path: instead of
demoting the whole uplink and failing over to a different one in the
group, the loop falls through to a Shadowsocks or WS wire on the
**same** uplink, keeping the operator's identity / weight / group
attribution intact.

```toml
[[outline.uplinks]]
name        = "edge-1"
group       = "main"
weight      = 1.0
transport   = "vless"
vless_xhttp_url = "https://cdn.example.com/SECRET/xhttp"
vless_id        = "00000000-0000-0000-0000-000000000000"
vless_mode      = "xhttp_h3"
cipher          = "2022-blake3-aes-256-gcm"
password        = "BASE64=="

  [[outline.uplinks.fallbacks]]
  transport   = "ws"
  tcp_ws_url  = "wss://ws.example.com/tcp"
  udp_ws_url  = "wss://ws.example.com/udp"
  tcp_mode    = "ws_h2"
  udp_mode    = "ws_h1"
  # cipher / password / fwmark / ipv6_first / fingerprint_profile
  # are inherited from the parent uplink unless overridden here.

  [[outline.uplinks.fallbacks]]
  transport   = "shadowsocks"
  tcp_addr    = "1.2.3.4:8388"
  udp_addr    = "1.2.3.4:8389"
```

### Fields

Every fallback entry carries its own wire-shape fields, mirroring the
top-level `[[outline.uplinks]]` schema **minus** the identity attributes
that belong to the parent (`name`, `weight`, `group`, `link`):

| Field | Required for | Notes |
|---|---|---|
| `transport` | always | `ws` / `shadowsocks` / `vless`. **No uniqueness restriction** — same-transport-as-parent and duplicate-transport entries are explicitly allowed. The most common cross-family shape is a VLESS primary on `xhttp_h*` with a VLESS fallback on `ws_h*` (same `transport = "vless"`, different carrier family, different dial URL); two SS fallbacks at distinct hosts as belt-and-suspenders also work. The dial loop and per-wire mode tracking treat each fallback as its own wire regardless of `transport`. |
| `tcp_ws_url`, `udp_ws_url`, `tcp_mode`, `udp_mode` | `transport = "ws"` | `tcp_ws_url` mandatory; `udp_ws_url` optional (UDP fallback opt-in). |
| `vless_ws_url`, `vless_xhttp_url`, `vless_mode`, `vless_id` | `transport = "vless"` | URL field must match the chosen `vless_mode` (xhttp\_\* → `vless_xhttp_url`; ws/quic → `vless_ws_url`). `vless_id` is per-wire-credential and **not** inherited from the parent — different VLESS endpoints use different uuids by definition. |
| `tcp_addr`, `udp_addr` | `transport = "shadowsocks"` | `tcp_addr` mandatory; `udp_addr` optional. |
| `cipher`, `password` | inherited | Default to the parent uplink's value. Override here to dial a fallback that uses a different shared secret. |
| `fwmark`, `ipv6_first`, `fingerprint_profile` | inherited | Same: default to the parent's, override per-fallback if needed. |

### Behaviour

#### Per-session dial loop

- For each new session the dial loop iterates wires in
  `wire_dial_order` — starting at the **active wire** (initially `0` =
  primary; advanced by the sticky-fallback state machine described
  below) and wrapping through the rest of the chain so primary is
  still tried as a last resort even when active is pinned to a
  fallback. The first wire that successfully dials carries the session.
- A successful dial is **invisible** to the load-balancer beyond an
  `outline_uplink_selected` metric tick. The parent's
  `report_runtime_failure` counter is only bumped when every wire on
  this uplink (primary + all fallbacks) has failed in the same
  session — so transient single-wire outages no longer demote the
  whole uplink as long as another wire works.
- Runtime failures attributed to a **specific wire** (chunk-0 failures
  carrying the failed wire's index, mid-session resets carrying the
  current relay wire's index) are gated on the same active-wire match
  the dial loop uses: a failure pinned to a wire that the manager has
  already moved away from is treated as session-local fallback churn,
  recorded only as a suppressed metric
  (`outline_ws_rust_uplink_runtime_failures_suppressed_total`), and
  does **not** stack onto the parent uplink's penalty / cooldown /
  consecutive-runtime-failures streak. Single-wire uplinks (no
  fallbacks declared) behave exactly as before — no "non-active wire"
  to suppress against.

#### Sticky fallback + auto-failback (active-wire state machine)

- After **`probe.min_failures` consecutive dial failures** of the wire
  that new sessions currently start with (`active_wire`), the dial
  loop advances `active_wire` to the next wire in the chain and pins
  it for `LoadBalancingConfig::mode_downgrade_duration` (one knob,
  two uses — per-wire mode downgrades and per-uplink active-wire
  pinning). Subsequent new sessions start at the sticky wire; the
  primary is still in the dial chain at the end so a recovered
  primary can still serve traffic if every other wire fails.
- When the pin expires `active_wire` snaps back to `0` (primary) so
  the next session retries the operator's first-choice wire. If
  primary is still broken the failure streak rebuilds and we end up
  pinned to the same fallback again — the timer is the rate-limit on
  retry, not a one-shot.
- **Early failback via probe recovery.** The probe (still primary-only
  in this iteration) drives an immediate snap-back to primary as soon
  as it accumulates `probe.min_failures` consecutive successes — the
  pin timer is not a hard wait. So a primary that recovers within a
  few probe cycles (typically 2 × `probe.interval_secs`) returns
  traffic to itself well before the 60-second pin would expire on its
  own. The same `min_failures` knob is the failure threshold and the
  success-stability threshold (one mental model: N consecutive probe
  outcomes flip the active wire in either direction).
- State is **per-transport**: TCP and UDP advance independently
  (`PerTransportStatus::active_wire` is split per transport).
  `outline_ws_rust_uplink_active_wire_index{transport}` exposes the
  current wire to dashboards.

#### Random forward-only rotation (`shuffle_wires = true`)

Opt-in per-uplink toggle that replaces the operator-ordered, wrap-
forever chain with a randomised, forward-only round:

```toml
[[outline.uplinks]]
name        = "edge-shuffled"
group       = "main"
transport   = "vless"
vless_xhttp_url = "https://cdn-a.example.com/SECRET/xhttp"
vless_id        = "00000000-0000-0000-0000-000000000000"
vless_mode      = "xhttp_h3"
shuffle_wires   = true

  [[outline.uplinks.fallbacks]]
  transport       = "vless"
  vless_xhttp_url = "https://cdn-b.example.com/SECRET/xhttp"
  vless_id        = "11111111-1111-1111-1111-111111111111"
  vless_mode      = "xhttp_h3"

  [[outline.uplinks.fallbacks]]
  transport       = "vless"
  vless_xhttp_url = "https://cdn-c.example.com/SECRET/xhttp"
  vless_id        = "22222222-2222-2222-2222-222222222222"
  vless_mode      = "xhttp_h3"
```

Semantics:

- **At config load**: the wire chain `[primary, fallbacks[0], …]` is
  reshuffled once with `rand::thread_rng()`. Each process restart
  picks a different ordering — the operator-configured primary may
  land at any position. The shuffle preserves the wire-set exactly
  (no wires dropped, duplicated, or corrupted) and parent-level
  identity (`name`, `weight`, `group`, `fingerprint_profile`) stays
  with the uplink regardless of which wire ended up at slot 0.
- **At runtime, all three failure sources drive forward-only wire
  rotation** through the same `record_wire_outcome` state machine:
  - **dial failures** (a fresh session can't connect on the active
    wire) — handled by the same dial-loop path as the legacy chain;
  - **probe failures** (`process_probe_err` /
    `run_fallback_wire_probe`) — advance `active_wire` on the
    probe-driven path and bump the round counter;
  - **runtime failures** (`report_runtime_failure*` — e.g.
    `ws upstream read idle for 300s on datagram channel`, mid-session
    transport resets, chunk-0 timeouts) — feed the per-wire streak
    so an established session repeatedly failing on the active wire
    advances rotation, not only flips uplink-level health.

  Without the runtime-failure feed, the dominant production failure
  mode (idle WS read on an established session) would never tick
  `active_wire` and dashboards would show no rotation despite the
  wire being demonstrably broken.
- **Round counter**: a per-transport `wires_failed_in_round`
  increments each time the active wire advances, regardless of which
  failure source drove the advance. The moment it reaches
  `total_wires` (every wire has been the active wire of a failed
  round since the last success), the uplink is forcibly marked
  `healthy = Some(false)` and pushed onto `failure_cooldown` — the
  load balancer picks another uplink for new sessions.
- **Round-gated healthy flip**: until the round counter reaches
  `total_wires`, the *uplink-level* `healthy = Some(false)` flip is
  **gated off** on the same uplink — both on the probe-driven path
  (`record_transport_failure`) and the runtime-driven path
  (`report_runtime_failure_inner`). Per-wire failure counters
  (`consecutive_failures`, `consecutive_runtime_failures`) still
  accumulate, but the LB does not drop the uplink from candidates
  prematurely — wire rotation gets a chance to traverse the chain
  before uplink-failover. Once the chain is exhausted, the gate
  releases and the flip lands.
- **Reset on any-wire success**: a successful dial of *any* wire
  (primary or fallback) zeroes the round counter and stamps
  `last_any_wire_success`; a successful probe also zeroes it
  (`record_transport_success`). Traffic stabilising on one wire
  restarts the round; the next failure resumes forward rotation
  from the wire that just worked, not from a fixed slot zero.
- **Per-wire failure budgets**: when active wire advances (via any
  path — dial, probe, runtime), `consecutive_failures` and
  `consecutive_runtime_failures` are reset to `0` so the new wire
  gets its own `min_failures` budget before being judged broken.

When to use it:

- You have several near-equivalent fallback endpoints (multiple
  CDNs, multiple SNIs to the same upstream, mirror Shadowsocks
  servers) and want different process restarts / replicas to
  spread load across them without the leftmost entry always taking
  the first hit.
- You want a definite "give up on this uplink" signal after one full
  pass through the chain rather than the legacy wrap-forever
  behaviour, so the load balancer reaches for the next uplink
  promptly when every wire of this uplink is degraded.

When **not** to use it:

- You have a clearly-preferred primary (fast, cheap) with fallbacks
  that exist only as last-resort overflow. Leave `shuffle_wires`
  off so the operator-ordered chain is respected and `auto_failback`
  drives recovery back to the configured primary.

The flag defaults to `false` — existing configs keep the legacy
operator-ordered chain and wrap-forever state machine bit-for-bit.

#### Mid-session handover (chunk-0 wire-aware failover)

- If a session's chunk-0 stalls (no first byte from upstream within
  `tcp_chunk0_failover_timeout`), the chunk-0 failover loop now first
  tries every **other wire on the same uplink** (Phase A) before
  jumping to a different uplink (Phase B). The X-Outline-Resume token
  issued for the failed wire rides into the wire-handover dial via
  the identity-level resume cache (see "Resume across wire switches"
  below), so handover-via-resume is seamless on a feature-enabled
  outline-ss-rust server. Wire-handover events surface on the
  failover counter as `transport="tcp_wire"`; cross-uplink failovers
  keep `transport="tcp"`.

#### Resume across wire switches

- Fallback TCP and UDP dials participate in
  `outline_transport::global_resume_cache()` keyed on
  `<uplink_name>#<transport>` — the **same identity-level key** the
  primary path uses. A primary VLESS dial that issued an
  `X-Outline-Resume` session id followed by a fallback WS dial after
  primary fails presents that token on the fallback dial; the
  server-side resume mechanism re-attaches the upstream session.
  Works for any combination where both wires carry the WS-resume
  header (WS, VLESS-WS, VLESS-XHTTP). Shadowsocks fallback has no WS
  layer and dials fresh — the user-visible session restart there is
  unavoidable.

#### Liveness override

- Without help, probe health on the primary wire would gate the whole
  uplink out of selection (`selection_health` → `effective_health` →
  false) and the fallback wire would never get a chance. To prevent
  that, an uplink with at least one fallback configured is treated as
  selectable when **any** wire — primary or fallback — has dialed
  successfully within `runtime_failure_window`. Single-wire uplinks
  keep their probe-only health gating intact (no false-positive
  liveness from stale primary successes).
- **Bootstrap pass-through.** The recent-success override needs at
  least one prior wire success to latch onto. When primary is
  probe-marked unhealthy from the very first probe (or comes up failing
  after a restart) and no wire has stamped `last_any_wire_success`
  yet, the selection layer admits the uplink anyway — provided
  fallbacks are configured and the transport is not in cooldown — so
  the dial loop has a chance to attempt the fallback. Without this,
  the dial loop (which used to be the only path that could stamp
  `last_any_wire_success`) and candidate filtering deadlock each
  other. Snapshot-side **effective health** does NOT use this
  bootstrap pass-through: a fallback wire that has not yet succeeded
  must not display as green. The dashboard goes green only after a
  fallback dial actually lands or the per-wire probe walk (below)
  validates it.
- **Per-wire probe walks.** When the primary probe fails this cycle
  AND the uplink has at least one fallback configured, the scheduler
  follows up with a probe targeted at the active fallback wire — wire
  index `max(active_wire, 1)` — using a synthetic per-wire view of the
  uplink (`UplinkConfig::wire_view`). On success, the fallback-wire
  probe stamps `last_any_wire_success` directly, so passive uplinks
  carrying no client traffic still get their fallback validated and
  surface as `*_health_effective = true` on dashboards. Bypasses
  warm-standby slots (those are keyed on the parent's primary wire)
  and skips parent-level penalty / cooldown bookkeeping — that
  scoring state is sized for primary's traffic patterns. The
  fallback-wire probe DOES feed its measured latency into the
  fallback wire's own per-wire EWMA slot, so cross-uplink scoring
  ranks this uplink by the wire actually carrying traffic instead of
  primary's (possibly stale) measurement.
- The same any-wire signal also drives **effective health** on the
  snapshot / Prometheus / dashboard. `UplinkSnapshot::tcp_health_effective`
  (and the corresponding `outline_ws_rust_uplink_health_effective` gauge)
  reflects "is this uplink delivering traffic?": probe-confirmed OR
  any-wire-recent-success. The legacy `tcp_healthy` /
  `outline_ws_rust_uplink_health` keeps the probe-only verdict for
  dashboards that specifically care about the primary wire. The HTML
  dashboard's row tone consults effective health, so an uplink whose
  primary is probe-down but whose fallback is delivering traffic
  renders green instead of red — visualization stays in sync with
  routing.

#### Bypass list

- The fallback dial bypasses the standby pool — that pool today is
  keyed on the parent's primary wire shape, and reusing it for a
  fallback wire would hand out a socket of the wrong transport. A
  per-wire warm-standby pool is the next step. The mode-downgrade
  window, by contrast, is already per-wire (see
  `fallback_mode_downgrades` and `effective_*_mode_for_wire`), so a
  fallback wire that observes its own carrier downgrade caps only
  its own slot.
- The DNS cache, per-uplink fingerprint scope, and the resume cache
  **are** preserved across wire switches.
- The RTT EWMA is now **per-wire**. Primary's measurement lives in
  the existing `rtt_ewma` slot on `PerTransportStatus`; each fallback
  wire has its own slot in `fallback_rtt_ewma` (lazy-extended on
  first write, indexed by `wire_index - 1`). The per-wire probe walk
  feeds the fallback wire's probe latency into its own slot, and
  cross-uplink scoring (`scoring_base_latency`) reads the EWMA of the
  currently active wire — so when the dial loop has flipped
  `active_wire` to a fallback, that fallback's measured RTT is what
  ranks this uplink against its peers, not primary's (possibly
  stale, possibly belonging to a now-broken wire) value. Cold start
  right after a wire flip — fallback slot still empty — falls back to
  primary's EWMA for one probe cycle until the per-wire probe stamps
  in.
- Two Prometheus gauges now expose RTT EWMA at different semantic
  layers. `outline_ws_rust_uplink_rtt_ewma_seconds{transport,uplink}`
  keeps the legacy primary-only verdict — useful for seeing the
  carrier health of the configured primary regardless of which wire
  is currently doing the work. `outline_ws_rust_uplink_active_wire_rtt_ewma_seconds{transport,uplink}`
  reports the EWMA of the wire actually carrying traffic; equals the
  legacy gauge when `active_wire == 0`, reads the matching
  `fallback_rtt_ewma` slot otherwise. Operators graphing user-visible
  latency / setting alerts on real-traffic RTT use the active-wire
  gauge; primary-health alerts stay on the legacy gauge.

#### UDP candidacy

- The UDP candidate filter (`supports_transport_for_scope`) consults
  `UplinkConfig::supports_udp_any()` so an uplink whose primary is
  TCP-only (e.g. SS without `udp_addr`) but whose fallback is
  UDP-capable still shows up for UDP dispatch.

#### VLESS-fallback wire types

- **All three wire shapes work as VLESS fallbacks** now: `ws_h1` /
  `ws_h2` / `ws_h3` (WS family), `xhttp_h1` / `xhttp_h2` / `xhttp_h3`
  (XHTTP family), and `quic` (raw QUIC). The QUIC mode rides through
  the same `VlessUdpHybridMux` machinery the primary VLESS-UDP path
  uses (QUIC mux + WS-over-H2 fallback factory), but every per-uplink
  hook is wired to *the fallback wire's* per-wire mode-downgrade slot
  rather than primary's. So a fallback wire's `quic` dial that fails
  and pivots to WS-H2 records the QUIC failure in its own slot, and
  subsequent dials of the same fallback wire skip QUIC outright until
  the wire's downgrade window expires — exactly mirroring primary's
  established behaviour, just without polluting primary's mode
  tracking.

### Inline `[outline]` shorthand

The single-uplink inline shape (`tcp_ws_url` etc. directly on
`[outline]`) does **not** expose fallback configuration — declare an
explicit `[[outline.uplinks]]` array entry to use fallbacks.
