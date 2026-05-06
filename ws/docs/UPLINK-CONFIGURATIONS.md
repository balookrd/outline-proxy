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
- **Sub-tables** (`ws` / `http` / `dns` / `tcp`) are replaced wholesale.
  If a group sets `[uplink_group.probe.http]`, the template's
  `[outline.probe.http]` is dropped for that group — repeat every field
  you still want.
- **Activation requires at least one of `ws` / `http` / `dns`** in the
  resulting (post-merge) probe config; otherwise the probe loop will not
  start for that group.

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
- `http` / `dns` / `tcp`: cannot be disabled per group. The merge uses
  `override.or(template)` ([groups.rs:160](src/config/load/groups.rs:160)),
  so an omitted sub-table inherits the template's value, and there is no
  syntax for "explicit none". To run a group without one of these probes
  while another group keeps it, remove the sub-table from
  `[outline.probe]` and re-declare it only inside the groups that need
  it via `[uplink_group.probe.<kind>]`.

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
Chrome 130 (Windows + macOS), Firefox 130 (Windows + macOS),
Safari 17 (macOS), Edge 130 (Windows). Selection is per `(host, port)`
under the stable strategy, so a single peer keeps a single identity
across reconnects.

The knob is opt-in. Default behaviour leaves the wire shape exactly
as in pre-fingerprint builds — no headers added beyond
`X-Outline-Resume-*`. Enable it via the top-level `fingerprint_profile`
key in `config.toml`:

```toml
# top-level — sibling of [socks5], [metrics], [outline], [[uplink_group]]
fingerprint_profile = "stable"
```

Accepted values:

- `"off"` / `"none"` / `"disabled"` / omitted — default, no headers added.
- `"stable"` / `"per_host_stable"` / `"per-host-stable"` / `"per-host"` —
  one identity per `(host, port)` for the lifetime of the process.
- `"random"` — fresh profile on every dial.

For embedded callers (tests, custom binaries) the strategy can also be
wired directly via the Rust API; the bootstrap binary picks the
config value at startup:

```rust
use outline_transport::{
    init_fingerprint_profile_strategy, FingerprintProfileStrategy,
};

init_fingerprint_profile_strategy(FingerprintProfileStrategy::PerHostStable);
```

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
| `transport` | always | `ws` / `shadowsocks` / `vless`; must differ from the parent's primary, and each transport may appear at most once across a single uplink's fallback list. |
| `tcp_ws_url`, `udp_ws_url`, `tcp_mode`, `udp_mode` | `transport = "ws"` | `tcp_ws_url` mandatory; `udp_ws_url` optional (UDP fallback opt-in). |
| `vless_ws_url`, `vless_xhttp_url`, `vless_mode`, `vless_id` | `transport = "vless"` | URL field must match the chosen `vless_mode` (xhttp\_\* → `vless_xhttp_url`; ws/quic → `vless_ws_url`). `vless_id` is per-wire-credential and **not** inherited from the parent — different VLESS endpoints use different uuids by definition. |
| `tcp_addr`, `udp_addr` | `transport = "shadowsocks"` | `tcp_addr` mandatory; `udp_addr` optional. |
| `cipher`, `password` | inherited | Default to the parent uplink's value. Override here to dial a fallback that uses a different shared secret. |
| `fwmark`, `ipv6_first`, `fingerprint_profile` | inherited | Same: default to the parent's, override per-fallback if needed. |

### Behaviour

- The dial loop tries `primary → fallbacks[0] → fallbacks[1] → …` on a
  single session basis. Each new session restarts at the primary; there
  is no per-uplink "active wire" memory in this iteration (Phase 2
  feature).
- A successful fallback dial is **invisible** to the load-balancer
  beyond an `outline_uplink_selected` metric tick. The parent's
  `report_runtime_failure` counter is only bumped when **every** wire
  on this uplink (primary + all fallbacks) has failed — so transient
  primary outages no longer demote the whole uplink as long as a
  fallback works.
- Probe still targets the **primary** transport in this iteration. The
  probe-confirmed health status of the parent uplink is read from the
  primary wire only; a flapping primary that always recovers via a
  fallback may still surface as `tcp_healthy = Some(false)` once the
  probe accumulates `min_failures` consecutive failures. Routing
  fallback to the active wire is a Phase-2 feature.
- The fallback dial bypasses the standby pool, mode-downgrade window,
  cross-transport resume cache, and RTT-EWMA feed — those structures
  are keyed on the parent's primary index/transport and are owned by
  the active-wire-aware machinery that lands in Phase 2. DNS cache and
  per-uplink fingerprint scope are preserved.
- UDP candidate filter (`supports_transport_for_scope`) consults
  `UplinkConfig::supports_udp_any()` so an uplink whose primary is
  TCP-only (e.g. SS without `udp_addr`) but whose fallback is
  UDP-capable still shows up for UDP dispatch.
- **Limitation:** VLESS as a *fallback transport on UDP* returns a
  clear error in this iteration. The QUIC-mux machinery in
  `acquire_udp_standby_or_connect` keys all per-uplink hooks on
  `candidate.index` and reusing those hooks for a fallback wire
  requires the upcoming active-wire plumbing. Use SS or WS for UDP
  fallback today.

### Inline `[outline]` shorthand

The single-uplink inline shape (`tcp_ws_url` etc. directly on
`[outline]`) does **not** expose fallback configuration — declare an
explicit `[[outline.uplinks]]` array entry to use fallbacks.
