<p align="center">
  <img src="docs/logo.png" alt="outline-ws-rust" width="320">
</p>

# outline-ws-rust

`outline-ws-rust` is a production-oriented Rust proxy that accepts local SOCKS5 traffic and forwards it to Outline-compatible WebSocket transports over HTTP/1.1, HTTP/2, or HTTP/3, or to VLESS-over-WebSocket uplinks.

It supports:

- SOCKS5 `CONNECT`
- SOCKS5 `UDP ASSOCIATE` and `hev-socks5` `UDP-in-TCP` (`CMD=0x05`)
- multi-uplink failover and load balancing
- WebSocket-over-HTTP/1.1, RFC 8441 (`ws-over-h2`), and RFC 9220 (`ws-over-h3`)
- VLESS-over-WebSocket uplinks (UUID auth, shared WSS dial path, per-destination UDP session-mux)
- one-line VLESS uplink config via `vless://UUID@HOST:PORT?...#NAME` share-link URIs (TOML `link = "..."`, CLI `--vless-link`, control-plane `link` payload field)
- Prometheus metrics, built-in multi-instance dashboard, and packaged Grafana dashboards
- existing TUN device integration for `tun2udp`
- stateful `tun2tcp` relay with production-oriented guardrails

---

*Русская версия: [README.ru.md](README.ru.md)*

## Overview

At a high level, the process does five jobs:

1. Accepts local SOCKS5 and optional TUN traffic.
2. Selects the best available uplink using health probes, EWMA RTT scoring, sticky routing, hysteresis, penalties, and warm standby.
3. Connects to an Outline WebSocket transport using the requested mode (`http1`, `h2`, or `h3`) with automatic fallback, or to a VLESS-over-WebSocket uplink.
4. Encrypts payloads using Shadowsocks AEAD, or frames them as VLESS with UUID auth, before sending them upstream.
5. Exposes Prometheus metrics for runtime, uplink, probe, TUN, and `tun2tcp` behavior.

## Architecture

```mermaid
flowchart LR
    subgraph LocalHost["Local host"]
        C["SOCKS5 clients"]
        T["Existing TUN device"]
        P["outline-ws-rust"]
        M["/metrics endpoint"]
        C --> P
        T --> P
        P --> M
    end

    subgraph Runtime["Proxy runtime"]
        S["SOCKS5 TCP + UDP handlers"]
        U["Uplink manager"]
        LB["Scoring and routing
EWMA RTT + weight + penalty
sticky + hysteresis"]
        WS["WS transport connectors
HTTP/1.1 / HTTP/2 / HTTP/3"]
        SS["Shadowsocks AEAD"]
        VL["VLESS framing
UUID auth"]
        TT["TUN engines
tun2udp + tun2tcp"]
    end

    P --> S
    P --> TT
    S --> U
    TT --> U
    U --> LB
    LB -->|"*_ws_mode = http1/h2/h3"| WS
    WS -->|"outline"| SS
    WS -->|"vless"| VL

    subgraph Upstream["Upstream uplinks"]
        O1["outline-over-ws (A/B)"]
        O4["vless-over-ws edge"]
    end

    SS --> O1
    VL --> O4

    subgraph Observability["Observability"]
        PR["Prometheus"]
        DASH["Built-in dashboard"]
        GD["Grafana dashboards"]
        AL["Alert rules"]
    end

    M --> PR
    P --> DASH
    PR --> GD
    PR --> AL
```

## Supported Features

### SOCKS5

- No-auth SOCKS5
- Optional username/password auth (`RFC 1929`)
- TCP `CONNECT`
- UDP `ASSOCIATE`
- `hev-socks5` `FWD UDP` / `UDP-in-TCP` (`CMD=0x05`)
- pipelined SOCKS5 handshake compatibility for `hev-socks5-tunnel`
- SOCKS5 UDP fragmentation reassembly on inbound client traffic
- IPv4, IPv6, and domain-name targets
- declarative policy routing by destination CIDR with per-rule file-backed lists (hot-reloaded), per-rule fallback (`fallback_via` / `fallback_direct` / `fallback_drop`), and a `direct` / `drop` built-in targets for bypass or policy blocks
- group-level tunnel bypass (`bypass_when_down` on the uplink group): while a group has no healthy uplink, traffic routed to it dispatches `direct` instead of failing, and returns to the tunnel as soon as any uplink recovers

### Outline transports

- `ws://` and `wss://`
- HTTP/1.1 Upgrade
- RFC 8441 WebSocket over HTTP/2
- RFC 9220 WebSocket over HTTP/3 / QUIC
- VLESS-over-XHTTP (`vless_mode = "xhttp_h1"`, `"xhttp_h2"` or `"xhttp_h3"`): pairs with the `xhttp_path_vless` listener on outline-ss-rust. The dial URL `vless_xhttp_url` selects the wire mode through its query string — bare URL or `?mode=packet-up` runs the GET + sequenced POSTs pair, `?mode=stream-one` runs a single bidirectional POST (h2 / h3 only; the h1 carrier supports packet-up only and bails on stream-one). Useful when WebSocket upgrades are blocked on the path (Cloudflare-style CDNs, captive-portal middleboxes).
- VLESS-over-WebSocket uplinks (`transport = "vless"`, UUID auth, shared WSS dial path with `ss`, per-destination UDP session-mux bounded by `vless_udp_max_sessions`)
- transport fallback:
  - `h3 -> h2 -> http1`
  - `h2 -> http1`
  - `xhttp_h3 -> xhttp_h2 -> xhttp_h1` on dial failure (packet-up only — stream-one stops at h2), carrying the same `X-Outline-Resume` token across each carrier switch so a feature-enabled outline-ss-rust server re-attaches the parked VLESS upstream instead of opening a fresh one. The h1 step is the last-resort fallback for paths blocking both QUIC and h2 ALPN; it dials two keep-alive sockets per session (long-lived GET + serialised POSTs) since h1 cannot multiplex.
  - **per-uplink fallback transports** via `[[outline.uplinks.fallbacks]]` — each uplink may declare additional wire shapes (different `transport` + URL/addr) that the dial loop tries when the primary fails on this uplink. Supports `vless → ss`, `ss → vless`, etc. After `probe.min_failures` consecutive dial failures the active wire becomes sticky for `mode_downgrade_secs` (one knob, two uses) and new sessions start at the fallback; auto-failback snaps back to primary on pin expiry. Resume tokens (`X-Outline-Resume`) ride through the wire switch via the identity-level resume cache, so handover-via-resume across `vless ↔ ss` is seamless on a feature-enabled server. The chunk-0 failover loop also tries every other wire on the *same* uplink before jumping to a different uplink (handover within uplink). Optional per-uplink `shuffle_wires = true` reshuffles the chain at process startup (collision-free permutations within an `[[uplink_group]]`) and surrenders to uplink-failover after one full forward pass without any wire success (round resets on any-wire success); `shuffle_timer = "1h"` rerolls `active_wire` on a per-uplink interval (`30s` / `5m` / `1h30m` / `2d` / bare seconds) and suppresses probe-driven early-failback to primary so the reroll stays visible. `carrier_downgrade = false` collapses the vertical carrier cascade so failures roll over wire-to-wire directly (useful against DPI that drops the whole upstream regardless of HTTP version). See [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md) "Per-uplink fallback transports".
- cross-transport client-side session resumption: WebSocket Upgrades carry `X-Outline-Resume-Capable: 1`; the server-issued `X-Outline-Session` ID is cached per uplink (and per (uplink, target) inside the VLESS UDP mux) and presented as `X-Outline-Resume: <hex>` on the next on-demand dial so a feature-enabled outline-ss-rust server can re-attach the parked upstream and skip the connect-to-target. Covers TCP-WS, SS-UDP-WS, and VLESS-over-XHTTP (h1 / h2 / h3, packet-up and stream-one alike — the token round-trips on the same response that delivers the first downlink chunk). Opt-in on the wire and zero-overhead when the server doesn't support it.

### Encryption

- `chacha20-ietf-poly1305`
- `aes-128-gcm`
- `aes-256-gcm`
- `2022-blake3-aes-128-gcm`
- `2022-blake3-aes-256-gcm`
- `2022-blake3-chacha20-poly1305`

### Uplink management

- multiple uplinks
- fastest-first selection
- selection mode:
  - `active_active`: new flows can use different uplinks based on score, stickiness, and failover
  - `active_passive`: keep the current selected uplink until it becomes unhealthy or enters cooldown. A manual control-plane switch or probe-driven failover that moves the active uplink off an in-flight SOCKS5 session now tears that TCP session down with RST (`SO_LINGER {l_onoff=1, l_linger=0}`) so the client reconnects through the new active uplink instead of egressing through the now-passive one (different source IP / ASN). UDP-side downlink loop wakes on the same `subscribe_active_uplinks` watch. Counter: `outline_ws_socks_tcp_strict_aborts_total`. `active_active` is unaffected — the watcher never arms there.
- routing scope:
  - `per_flow`: decisions are made independently per routing key / target
  - `per_uplink`: one active uplink is shared process-wide per transport (`tcp` and `udp`); in `active_passive` mode the pinned TCP and UDP uplinks do not expire with `sticky_ttl`, established SOCKS TCP tunnels stay pinned to the uplink that completed setup while non-migratable flows that still depend on the older active uplink may be reselected or closed after a switch, and penalty history is not folded into the strict per-transport score
  - `per_client`: each ingress client sticks to one balancer-chosen uplink, keyed by the client's source IP (SOCKS5 peer IP, or the LAN device IP behind a TUN router) for `sticky_ttl` and refreshed while active; distinct clients spread across the uplinks while any single client keeps a stable egress IP instead of fanning its flows out, with failover when its pinned uplink goes unhealthy (`active_active` only — behaves like `per_flow` under `active_passive`; clients with no determinable source IP collapse to one shared key)
  - `global`: one shared process-wide active uplink is used for new user traffic across both `tcp` and `udp`; selection is intentionally biased toward TCP score, but a UDP-capable active uplink is considered failed when its UDP probe marks it unhealthy or its UDP runtime cooldown is active, the active global uplink does not expire with `sticky_ttl`, penalty history is not folded into the strict global score, and TUN flows that remain pinned to an older uplink after a global switch are actively closed so they reconnect through the new global uplink
- per-uplink static `weight`
- RTT EWMA scoring
- failure penalty model with decay
- sticky routing with TTL
- hysteresis to avoid unnecessary churn
- runtime failover
- auto-failback disabled by default (`auto_failback = false`): switches only on failure, never proactively back to a recovered primary
- warm-standby WebSocket pools for TCP and UDP
- active-uplink selection persisted across restarts (TOML state file, debounced async writes)

### Health probing

- WebSocket connectivity probes (TCP+TLS+WS handshake; no ping/pong — servers rarely respond to WebSocket ping control frames)
- real HTTP probes over `websocket-stream`
- real DNS probes over `websocket-packet`
- TLS handshake-only probes against a real product SNI through the tunnel — reproduces the user-flow chunk-0 failure pattern when upstream filtering silently drops `ServerHello` records, which the plain HTTP probe cannot see
- probe concurrency limits
- separate probe dial isolation
- immediate probe wakeup on runtime failure to accelerate detection
- consecutive-success counter for stable auto-failback gating

### TUN

- existing TUN device integration only
- `tun2udp` with flow lifecycle management, IPv4/IPv6 IP fragment reassembly, and local ICMP echo replies
- stateful `tun2tcp` relay with retransmit, zero-window persist/backoff, SACK-aware receive/send behavior, adaptive RTO, and bounded buffering

### Operations

- Prometheus metrics
- built-in multi-instance dashboard
- packaged Grafana dashboards
- proactive uplink TLS certificate-expiry monitoring (dashboard chip + Prometheus gauge `outline_ws_uplink_cert_expiry_timestamp_seconds`)
- hardened systemd unit
- Linux `fwmark` / `SO_MARK`
- IPv6-capable listeners, upstreams, probes, and SOCKS5 targets

## Current Limits

The project is intentionally practical, but there are still boundaries:

- `tun2tcp` is production-oriented but still not a kernel-equivalent TCP stack.
- Non-echo ICMP traffic on TUN is not supported.
- `probe.http` supports `http://` only — for HTTPS use the dedicated `[outline.probe.tls]` block, which drives a TLS handshake (no HTTP exchange) against a configured SNI. `probe.tcp` should target a speak-first TCP service such as SSH or SMTP, not a typical HTTP/HTTPS port.
- TCP failover is safe before useful payload exchange; live established TCP tunnels cannot be migrated transparently between uplinks.

## Repository Layout

- [`config.toml`](config.toml) - example configuration
- [`systemd/outline-ws-rust.service`](systemd/outline-ws-rust.service) - hardened systemd unit
- [`grafana/outline-ws-rust-dashboard.json`](grafana/outline-ws-rust-dashboard.json) - main operational dashboard
- [`grafana/outline-ws-rust-hang-diagnostics.json`](grafana/outline-ws-rust-hang-diagnostics.json) - situational hang diagnostics
- [`src/bootstrap/`](src/bootstrap) - startup sequence: listener binding and persistent state store
- [`src/config/`](src/config) - configuration loading, schema, and validated types
- [`src/proxy/`](src/proxy) - SOCKS5 TCP/UDP ingress handlers (dispatcher, TCP failover, UDP relay)
- [`crates/outline-uplink/`](crates/outline-uplink) - uplink selection, probing, failover, and standby management
- [`crates/outline-transport/`](crates/outline-transport) - WebSocket / HTTP-2 / HTTP-3 / VLESS transports + the cross-transport `ResumeCache`
- [`crates/outline-net/`](crates/outline-net) - DNS cache and shared net plumbing extracted from `outline-transport`
- [`crates/outline-tun/`](crates/outline-tun) - stateful TUN relay engines (TCP and UDP)
- [`crates/shadowsocks-crypto/`](crates/shadowsocks-crypto) - AEAD crypto helpers for Shadowsocks
- [`crates/outline-metrics/`](crates/outline-metrics) - Prometheus metrics registration and session/transport snapshots
- [`crates/outline-routing/`](crates/outline-routing) - CIDR routing table
- [`crates/socks5-proto/`](crates/socks5-proto) - SOCKS5 protocol primitives
- [`PATCHES.md`](PATCHES.md) - local vendored patch inventory

## Build

### Prerequisites

- Rust toolchain (stable): `rustup update stable`
- For cross-compilation: [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) — wraps the Zig C compiler to eliminate the need for a dedicated cross-linker per target.

```bash
cargo install cargo-zigbuild
```

Shortcuts available in this repository:

```bash
cargo release-musl-x86_64
cargo release-musl-aarch64
```

### CI Releases

- Every push to `main` triggers the `Nightly Release` workflow.
- That workflow moves the rolling tag `nightly` to the current `main` commit and republishes the `Nightly` GitHub prerelease.
- Nightly publishes server `release` artifacts for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, plus `SHA256SUMS.txt`.
- Nightly server archives are named `outline-ws-rust-vnightly-<full-commit-sha>-<target>.tar.gz`.
- To cut a stable release, run the manual `Release` workflow and pass `major_minor` such as `1.7`.
- CI finds the latest `v1.7.*` tag, increments the patch automatically, updates `Cargo.toml` and `Cargo.lock`, creates a release commit, and pushes that commit to `main`.
- After the release commit lands on `main`, create and push a signed tag locally; the tag push triggers the `Tag Release` workflow, which builds and publishes the GitHub Release.
- The stable release includes server `release` assets for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- Pushing a tag like `v1.2.3` manually still triggers the `Tag Release` workflow as a separate external tag-driven path.

Install the required Rust targets:

```bash
# VMs / servers
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```

---

### Feature flags

The binary is controlled by Cargo feature flags. Mix and match as needed:

| Feature | Default | Effect |
|---|---|---|
| `h3` | ✓ | H3/QUIC transport (pulls in quinn + sockudo-ws/http3) |
| `metrics` | ✓ | Prometheus metrics endpoint; also enables transport-layer metrics (pulls in prometheus + serde_json) |
| `tun` | ✓ | TUN device support (tun2udp + tun2tcp engines); remove to exclude all TUN code |
| `mimalloc` | ✓ | Replace the system allocator with mimalloc; reduces RSS fragmentation under connection churn. A background thread periodically runs `mi_collect` to hand freed memory back to the OS after traffic bursts |
| `env-filter` | ✓ | Dynamic `RUST_LOG` parsing; disable to hardcode log level at `WARN` and save ~300 KB on MIPS |
| `multi-thread` | ✓ | Tokio work-stealing scheduler; disable to force `current_thread` and save ~100–200 KB |

---

### Virtual machines and servers

Native build for the current machine (fastest, uses all CPU features):

```bash
cargo build --release
```

Static x86-64 binary (runs on any Linux x86-64 without glibc dependency):

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl
# or shorter
cargo release-musl-x86_64
```

Static AArch64 binary (ARM64 servers, AWS Graviton, Ampere):

```bash
cargo zigbuild --release --target aarch64-unknown-linux-musl
# or shorter
cargo release-musl-aarch64
```

To disable only one feature while keeping others (e.g. strip metrics but keep H3):

```bash
cargo zigbuild --release --no-default-features --features h3 --target x86_64-unknown-linux-musl
```

## Quick Start

Minimal local run using `config.toml`:

```bash
cargo run --release
```

Example one-shot CLI override:

```bash
cargo run --release -- \
  --listen [::]:1080 \
  --tcp-ws-url wss://example.com/SECRET/tcp \
  --tcp-mode h3 \
  --udp-ws-url wss://example.com/SECRET/udp \
  --udp-mode h3 \
  --method chacha20-ietf-poly1305 \
  --password 'Secret0'
```

Example client settings:

- SOCKS5 host: `::1` or `127.0.0.1`
- SOCKS5 port: `1080`

For `listen = "[::]:1080"`, many systems create a dual-stack listener. If your platform does not map IPv4 to IPv6 sockets, bind an additional IPv4 listener instead.

### `hev-socks5-tunnel` compatibility

`outline-ws-rust` accepts both UDP relay modes used by [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel):

```yaml
socks5:
  address: '127.0.0.1'
  port: 1080
  udp: 'udp'      # standard SOCKS5 UDP ASSOCIATE
  # udp: 'tcp'    # hev FWD UDP / UDP-in-TCP (CMD=0x05)
  # pipeline: true
```

- `udp: 'udp'` uses standard SOCKS5 `UDP ASSOCIATE`.
- `udp: 'tcp'` uses the proprietary `hev-socks5` TCP-carried UDP relay (`CMD=0x05`), which is also supported.
- `pipeline: true` is accepted, including when username/password auth is enabled.

## Configuration

By default the process reads [`config.toml`](config.toml).

Example:

```toml
[socks5]
# Optional. If omitted, the SOCKS5 listener is disabled.
listen = "[::]:1080"
# Optional local SOCKS5 auth for clients.
#
# [[socks5.users]]
# username = "alice"
# password = "secret1"
#
# [[socks5.users]]
# username = "bob"
# password = "secret2"

[metrics]
listen = "[::1]:9090"

# Control plane (mutating endpoints, e.g. /switch). Must be bound on a
# separate socket from [metrics] and is always gated by a bearer token.
# Omit the section entirely to disable mutating endpoints.
# [control]
# listen = "127.0.0.1:9091"
# token = "long-random-secret"
# # Or read the token from a sidecar file (path resolved relative to this
# # config). Use this when secrets must not live in the config itself.
# # token_file = "/etc/outline-ws/control.token"

# Built-in multi-instance dashboard. Open http://LISTEN/dashboard.
# Secrets stay in the dashboard process config and are never sent to the
# browser. Each instance must expose its own [control] listener.
# [dashboard]
# listen = "127.0.0.1:9092"
# refresh_interval_secs = 5
# # Per-instance control HTTP request timeout (default 5s).
# request_timeout_secs = 5
#
# [[dashboard.instances]]
# name = "inst-01"
# # http:// or https:// — TLS control endpoints are supported.
# control_url = "http://127.0.0.1:9091"
# token_file = "/etc/outline-ws/inst-01.control.token"
#
# [[dashboard.instances]]
# name = "inst-02"
# control_url = "https://10.0.0.12:9091"
# token = "long-random-secret"

[tun]
# Existing TUN device path. Creation, IP addresses and routes stay outside the app.
# Linux example:
# path = "/dev/net/tun"
# name = "tun0"
# macOS / BSD example:
# path = "/dev/tun0"
# mtu = 1500
# Per-table cap on concurrent UDP flows. Applies independently to tunnelled
# flows and to direct (`via = "direct"`) flows; when a table is full the
# least-recently-seen flow in it is evicted. Default 4096.
# max_flows = 4096
# idle_timeout_secs = 300
# Process-wide cap on concurrent upstream dials, shared by the TCP and UDP
# engines. A flow burst dials one carrier handshake (TLS/WS/QUIC) per flow;
# over the cap, connect tasks queue for a permit (held for the dial only, never
# the flow's lifetime) and the burst handshakes in fast waves instead of all at
# once. Steady-state flow concurrency is unaffected. 0 disables the gate.
# max_concurrent_upstream_dials = 32
# Built-in IKE / IPsec NAT-T bypass — see "TUN Mode" section below.
# ipsec_bypass = false
# Allow ICMP PTBs that advertise a path MTU below QUIC's Initial-datagram
# minimum (1200 v4 / 1280 v6) on TUN UDP oversize drops. Default false
# protects QUIC clients from being evicted to TCP; set true for VoWiFi /
# IKE-only setups (`docs/TUN-PMTUD.md`).
# pmtud_emit_below_quic_initial = false
# QUIC connection sniffing (Xray-style destOverride; default on). Recovers the
# SNI from the first datagram's QUIC Initial ClientHello and sends the domain
# (not the IP) upstream so the exit node resolves it. Mirrors [tun.tcp] sniffing.
# sniff_quic = true
# Domains excluded from sniff override (TCP + QUIC): a sniffed host matching any
# suffix keeps the literal IP instead of a domain. For sites where the client's
# own DNS beats the exit re-resolving (geo-wrong CDN edge). Default empty.
# sniff_override_exclude = ["strava.com"]

# [tun.tcp]
# connect_timeout_secs = 10
# handshake_timeout_secs = 15
# half_close_timeout_secs = 60
# max_pending_server_bytes = 4194304
# backlog_abort_grace_secs = 3
# backlog_hard_limit_multiplier = 2
# backlog_no_progress_abort_secs = 8
# max_buffered_client_segments = 4096
# max_buffered_client_bytes = 2097152
# Uplink receive-window auto-tuning: a new flow advertises this much in the
# SYN-ACK and earns the rest of max_buffered_client_bytes as its bytes actually
# drain upstream — so a burst of still-dialling flows buffers N x 64 KiB
# instead of N x 2 MiB. 0 starts every flow at the full window (old behaviour).
# initial_receive_window_bytes = 65536
# max_retransmits = 12
# Connection sniffing (Xray-style destOverride; default on). Peeks the first
# client bytes, recovers the host from the TLS SNI / HTTP Host, and sends the
# domain (not the IP) upstream so the exit node resolves it. (QUIC sniffing is
# the [tun] sniff_quic knob; per-domain opt-outs via [tun] sniff_override_exclude.)
# sniffing = true
# sniff_timeout_ms = 300
# SNI bypass for DIRECT flows: re-resolve a sniffed domain via THIS node's local
# resolver and dial that IP instead of the client's literal IP — fixes bypassed
# domains the client resolved to a dead/unreachable IP. Default false.
# sniff_direct_reresolve = false
# Carrier migration (default on): when the shared carrier a tunnelled flow rides
# dies, re-dial, have the server re-attach the upstream it parked, replay the
# byte gap both ways, and keep the flow running instead of resetting the app's
# connection. Engages ONLY on a confirmed server-side resume hit, so it is inert
# against a server with resumption disabled (the server default). See "TUN Mode".
# carrier_migration = true

# [outline.probe] acts as a template inherited by every [[uplink_group]].
# Individual groups can override any field via [uplink_group.probe].
[outline.probe]
interval_secs = 30
timeout_secs = 10
max_concurrent = 4
max_dials = 2
min_failures = 1

[outline.probe.ws]
enabled = true

[outline.probe.http]
# Single URL:
#   url = "http://example.com/"
# Or a rotation list — one URL per probe call, advancing through the list.
# Spreading probe load across multiple endpoints surfaces per-site outages
# instead of masking them behind one always-reachable target. The cursor is
# shared across all uplinks in the group, so consecutive probe calls within
# a cycle hit consecutive entries.
urls = [
    "http://example.com/",
    "http://www.iana.org/",
]

# `outline.probe.http` sends an HTTP `HEAD` request (not `GET`), so health
# checks do not download response bodies through the uplink. Any HTTP status
# in the `200..400` range counts as success — `301`/`302` redirects are fine.

# Optional: TLS handshake-only probe. Reproduces the user-flow chunk-0
# pattern when upstream filtering silently drops `ServerHello` records for
# specific SNIs — invisible to `[outline.probe.http]` because plain HTTP
# never exercises TLS. Mutually exclusive with `[outline.probe.http]` /
# `[outline.probe.tcp]` (priority: tls → http → tcp). Metrics emit
# `probe="tls"`. See docs/UPLINK-CONFIGURATIONS.md "TLS handshake-only
# data-path probe" for target selection guidance.
# [outline.probe.tls]
# targets = [
#   "www.youtube.com:443",
#   "www.instagram.com",  # bare host → port 443
# ]

[outline.probe.dns]
server = "1.1.1.1"
port = 53
name = "example.com"

# Each uplink group is an isolated UplinkManager with its own probe loop,
# standby pool, sticky-routes store, active-uplink state, and LB policy.
# Note: [[uplink_group]] stays at the top level, not under [outline].
[[uplink_group]]
name = "main"
mode = "active_active"
routing_scope = "per_flow"
warm_standby_tcp = 1
warm_standby_udp = 1
sticky_ttl_secs = 300
hysteresis_ms = 50
failure_cooldown_secs = 10
tcp_chunk0_failover_timeout_secs = 10
rtt_ewma_alpha = 0.3
failure_penalty_ms = 500
failure_penalty_max_ms = 30000
failure_penalty_halflife_secs = 60
h3_downgrade_secs = 60
# auto_failback = false
# VLESS UDP session-mux bounds (only used by transport = "vless" uplinks).
# vless_udp_max_sessions = 256              # LRU-evict beyond this many targets
# vless_udp_session_idle_secs = 60          # 0 disables idle eviction
# vless_udp_janitor_interval_secs = 15

# Uplinks live under [outline]. Each [[outline.uplinks]] entry must declare
# `group = "..."` matching an [[uplink_group]].name above.
[[outline.uplinks]]
name = "primary"
group = "main"
transport = "ss"
tcp_ws_url = "wss://example.com/SECRET/tcp"
weight = 1.0
tcp_mode = "h3"
# fwmark = 100
# ipv6_first = true
udp_ws_url = "wss://example.com/SECRET/udp"
udp_mode = "h3"
method = "chacha20-ietf-poly1305"
password = "Secret0"

[[outline.uplinks]]
name = "backup"
group = "main"
transport = "ss"
tcp_ws_url = "wss://backup.example.com/SECRET/tcp"
weight = 0.8
tcp_mode = "h2"
udp_ws_url = "wss://backup.example.com/SECRET/udp"
udp_mode = "h2"
method = "chacha20-ietf-poly1305"
password = "Secret0"

# VLESS-over-WebSocket uplink. Shares the WSS dial path with the "ss"
# transport; `vless_id` replaces the Shadowsocks cipher/password. The VLESS
# server exposes one WS path (`ws_path_vless`) shared by TCP and UDP, so the
# client takes a single `vless_ws_url`/`vless_mode` pair — using
# `tcp_ws_url`/`udp_ws_url` with `transport = "vless"` is rejected at parse
# time.
[[outline.uplinks]]
name = "vless-edge"
group = "main"
transport = "vless"
vless_ws_url = "wss://vless.example.com/SECRET/vless"
vless_mode = "h2"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 0.5

# Same VLESS uplink configured from a single share-link URI. The loader
# expands the URI into the matching `vless_id` / `vless_*_url` /
# `vless_mode` triple at startup; mixing `link` with the explicit fields
# is rejected. Recognises the standard Xray / V2Ray query parameters
# (`type`, `security`, `path`, `alpn`, `mode`). See
# docs/UPLINK-CONFIGURATIONS.md "VLESS share-link URIs" for the full
# parameter table.
[[outline.uplinks]]
name = "vless-share"
group = "main"
link = "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?type=ws&security=tls&path=%2FSECRET%2Fvless&alpn=h2#vless-edge"
weight = 0.5

# Optional policy routing — first-match-wins by destination CIDR.
# `via` accepts a group name or the reserved `direct` / `drop` targets.
# Omit [[route]] entirely to send everything through the first group.
[[route]]
prefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
via = "direct"

[[route]]
default = true
via = "main"
```

### Key config behavior

- `transport` accepts `ss` (default; alias `shadowsocks`) or `vless`. The legacy `ws` / `websocket` values are deprecated aliases for `ss` and will be removed in a future release. VLESS shares the WSS dial path with `ss` (same `tcp_ws_url` / `udp_ws_url` / `tcp_mode` / `udp_mode` / `ipv6_first` / `fwmark` fields) but authenticates with a single `vless_id` instead of a Shadowsocks `method` + `password`. VLESS UDP opens one WSS session per destination inside the uplink (bounded by `[outline.load_balancing] vless_udp_max_sessions`, LRU-evicted, with idle eviction controlled by `vless_udp_session_idle_secs`).
- `link = "vless://UUID@HOST:PORT?type=...&security=...&alpn=...#NAME"` configures a VLESS uplink from a single share-link URI in lieu of the explicit `vless_id` / `vless_*_url` / `vless_mode` fields; `transport = "vless"` is implied. The same value is accepted via the `--vless-link` CLI flag (`OUTLINE_VLESS_LINK`) and the `/control/uplinks` REST payload (`link`, alias `share_link`). Mixing `link` with the explicit fields is rejected. See [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md#7-vless-share-link-uris) for the recognised query-parameter table and constraints.
- At least one ingress must be configured: `--listen` / `[socks5].listen` and/or `[tun]`. If neither is present, the process exits with an error instead of silently binding `127.0.0.1:1080`.
- `tcp_mode` / `udp_mode` (`transport = "ss"`) and `vless_mode` (`transport = "vless"`) pick the per-direction transport carrier: `ws_h1` / `ws_h2` / `ws_h3` (WebSocket Upgrade), or `xhttp_h1` / `xhttp_h2` / `xhttp_h3` (VLESS-only XHTTP packet-up). See [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md) for per-shape config blocks, dial-time fallback chains, and resume behaviour.
- `ipv6_first` (default `false`) changes resolved-address preference for that uplink from IPv4-first to IPv6-first for TCP, UDP, H1, H2, and H3 connections.
- `method` also accepts `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`; for these methods `password` must be a base64-encoded PSK of the exact cipher key length.
- `[[socks5.users]]` enables local SOCKS5 username/password auth for multiple users. Each entry must include both `username` and `password`.
- `[socks5] username` + `password` is still accepted as a shorthand for a single user.
- CLI/env equivalents `--socks5-username` / `SOCKS5_USERNAME` and `--socks5-password` / `SOCKS5_PASSWORD` also configure a single user.
- The same SOCKS5 listener accepts both standard `UDP ASSOCIATE` and `hev-socks5` `UDP-in-TCP` (`CMD=0x05`); no extra config switch is required on the server.
- `[outline.probe] min_failures` (default `1`): consecutive probe failures required before an uplink is declared unhealthy. Increase to `2` or `3` to tolerate intermittent probe blips without triggering failover. The same value also sets the consecutive-success stability threshold for `auto_failback`.
- `[outline.load_balancing] tcp_chunk0_failover_timeout_secs` (default `10`): how long the proxy waits for the first upstream response bytes after the most recent client request activity before allowing TCP chunk-0 failover to another uplink. Increase this if links still switch on slow first-byte responses. (Applies to single-group configs; for multi-group setups the same field lives on each `[[uplink_group]]`.)
- `[outline.load_balancing] auto_failback` (default `false`): controls whether the proxy proactively returns traffic to a recovered higher-priority uplink.
  - `false` (default): the active uplink is replaced **only when it fails**. Once on a backup, the proxy stays there until the backup itself fails — no automatic return to primary. Recommended for production use to prevent unnecessary connection disruption.
  - `true`: when the current active is healthy and a candidate with a **higher `weight`** (or equal weight and lower config index) exists, the proxy may return traffic to that candidate — but only after the candidate has accumulated `min_failures` consecutive successful probe cycles. Priority is determined by `weight`, not EWMA RTT: this prevents spurious switches under load, when the active uplink's EWMA temporarily inflates due to slow connections while an idle backup looks better by latency. Failback always moves toward higher weight (`1.0 → 1.5 → 2.0`): switching to a lower-weight uplink via auto_failback is not possible — that requires a probe-confirmed failover.
- `h3_downgrade_secs` (per-group, default `60`, also accepted as `mode_downgrade_secs`): how long an uplink that experienced a failure on its advanced mode — an H3 application-level error (e.g. `H3_INTERNAL_ERROR`) — stays in H2 fallback mode before the original mode is retried. Applies to both `transport = "ss"` and `transport = "vless"`. Set to `0` to disable automatic downgrade.
- `state_path` (optional): path to a TOML file where the active-uplink selection is persisted across restarts. Defaults to the config file path with the extension replaced by `.state.toml` (e.g. `config.toml` → `config.state.toml`). If the file cannot be written (e.g. config lives in a read-only `/etc/` directory under `ProtectSystem=strict`), the process logs a warning at startup and continues without persistence. The bundled systemd units set `STATE_PATH=/var/lib/outline-ws-rust/state.toml` so the state lands in the writable state directory. Only the active-uplink selection is persisted (by uplink name); EWMA and penalty values are not — they are re-established within one probe cycle after restart.
- Uplink groups (`[[uplink_group]]`) each hold their own probe loop, standby pool, sticky-routes store, active-uplink state, and load-balancing policy — groups are fully isolated at runtime.
- `[outline.probe]` acts as a template: each group inherits it, and `[uplink_group.probe]` overrides individual fields per group. Probe sub-tables (`ws`/`http`/`dns`/`tcp`/`tls`) are replaced wholesale — if a group sets `[uplink_group.probe.http]`, the template's `[outline.probe.http]` is dropped for that group. Application-level probes (`http`/`tcp`/`tls`) are mutually exclusive: one runs per cycle, priority `tls → http → tcp`.
- Uplink names must be globally unique across all groups (Prometheus labels currently use `uplink="..."` without a group qualifier).
- The legacy `[bypass]` section has been removed. Migrate bypass prefixes to a `[[route]]` with `via = "direct"`. Loading a config that still has a `[bypass]` table fails with an explicit migration error.
- Uplinks, the probe template, and load-balancing settings all live under `[outline]` (`[[outline.uplinks]]`, `[outline.probe]`, `[outline.load_balancing]`). The older flat layout with top-level `tcp_ws_url` / `[probe]` / `[[uplinks]]` / `[load_balancing]` is still accepted for backwards compatibility and logs a deprecation warning on startup — migrate to the `[outline]` section. Without any `[[uplinks]]` entry, top-level `tcp_ws_url` / `password` / CLI flags (`--tcp-ws-url`, `--password`, …) synthesise a single-uplink `default` group as a shorthand.
- CLI flags and environment variables can override file settings.
- `--metrics-listen` can enable metrics even if `[metrics]` is not present.
- `--control-listen` / `CONTROL_LISTEN` and `--control-token` / `CONTROL_TOKEN` can enable the control plane without `[control]` in the config. Both must be supplied together; either alone is rejected at startup.
- `--tun-path` can enable TUN even if `[tun]` is not present.
- `direct_fwmark` (optional, top-level): `SO_MARK` value applied to TCP and UDP sockets opened for `direct`-routed connections. Use when bypass traffic must be tagged for OS-level policy routing to avoid loops (e.g. the bypass route must itself not be intercepted by the TUN interface).
- SOCKS5 → upstream TCP sessions are subject to a 5-minute bidirectional idle timeout. If no bytes flow in either direction for 300 seconds, the tunnel is closed and FDs are reclaimed. Any data activity in either direction resets the timer. This prevents FD accumulation from abandoned connections, particularly under TUN interceptors that open many TCP sessions and release them without FIN.
- Half-open TCP sessions (client sent EOF, proxy is waiting for upstream FIN) are closed after 30 seconds. This prevents sockets from staying half-open indefinitely when the upstream does not acknowledge the client's disconnect.

### Useful CLI and env overrides

- `--config` / `PROXY_CONFIG`
- `--listen` / `SOCKS5_LISTEN`
- `--socks5-username` / `SOCKS5_USERNAME`
- `--socks5-password` / `SOCKS5_PASSWORD`
- `--tcp-ws-url` / `OUTLINE_TCP_WS_URL`
- `--tcp-mode` / `OUTLINE_TCP_MODE`
- `--udp-ws-url` / `OUTLINE_UDP_WS_URL`
- `--udp-mode` / `OUTLINE_UDP_MODE`
- `--method` / `SHADOWSOCKS_METHOD`
- `--password` / `SHADOWSOCKS_PASSWORD`
- `--metrics-listen` / `METRICS_LISTEN`
- `--tun-path` / `TUN_PATH`
- `--tun-name` / `TUN_NAME`
- `--tun-mtu` / `TUN_MTU`
- `--fwmark` / `OUTLINE_FWMARK`
- `--state-path` / `STATE_PATH`

## Policy routing

Declarative routing by destination CIDR, evaluated first-match-wins with an explicit `default = true` rule. Each rule picks one of three targets via `via = "..."`:

- **a group name** (one of the declared `[[uplink_group]]`s) — the connection goes through that group's uplink manager;
- **`direct`** — forwarded outside any uplink (equivalent to the old `[bypass]` behaviour);
- **`drop`** — SOCKS5 `REP=0x02 (connection not allowed)` for TCP, silent drop for UDP.

IP targets are matched against each rule's CIDR prefixes. Domain-name targets (e.g. a SOCKS5 client that hands over a hostname for remote resolution) can never match a CIDR prefix — they are matched against each rule's `domains` suffixes instead, and fall through to the default when no rule lists them. The proxy deliberately does not resolve a domain locally just to route it: that would leak DNS outside the tunnel and break the remote-resolve contract.

### Route config

```toml
# RFC 1918 / ULA / loopback — never through a tunnel.
[[route]]
prefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1/128"]
via = "direct"

# Country or GeoIP list loaded from a file and hot-reloaded on mtime change.
[[route]]
file = "/etc/outline-ws-rust/geoip-cn.list"
file_poll_secs = 60
via = "backup"
fallback_via = "main"     # try "main" if "backup" has no healthy uplinks

# Multiple files merged into one rule — e.g. split IPv4 / IPv6 lists that
# come from separate upstream feeds. All listed files are watched and
# reloaded independently; inline `prefixes` may still be combined with them.
[[route]]
files = [
    "/etc/outline-ws-rust/geoip-cn-v4.list",
    "/etc/outline-ws-rust/geoip-cn-v6.list",
]
file_poll_secs = 60
via = "backup"

# Block a specific range.
[[route]]
prefixes = ["198.51.100.0/24"]
via = "drop"

# Domain targets (SOCKS5h hostnames): local zones stay direct…
[[route]]
domains = ["home.arpa", "corp.example"]
domain_file = "/etc/outline-ws-rust/bypass-domains.lst"
via = "direct"

# …every other domain goes through the tunnel instead of the default.
[[route]]
domains = ["*"]
via = "main"

# Explicit default — matches everything not caught above.
[[route]]
default = true
via = "main"
fallback_direct = true    # or: fallback_drop = true / fallback_via = "backup"
```

Rule fields:

- `prefixes` / `file` / `files`: inline list and/or one or more paths to files (one CIDR per line, `#` comments and blank lines ignored). All sources are merged into the rule's CIDR set. `file` is a convenience shorthand for a single-entry `files`; both may be combined.
- `domains` / `domain_file` / `domain_files`: domain suffixes this rule matches **domain targets** against (same file format, one suffix per line). `example.com` matches the domain itself and any subdomain (`a.b.example.com`), on label boundaries only; matching is case-insensitive and a trailing dot is ignored; `.example.com` and `*.example.com` are accepted spellings of the same suffix. The special pattern `"*"` matches every domain — use it as a catch-all rule so domain targets get an explicit route instead of the default. A rule may combine CIDR and domain sources: IPs match the CIDR side, domains the domain side.
- `file_poll_secs`: how often (in seconds) to `stat` each file and reload its contents on mtime change. Default `60`. Applies to every path in `files` and `domain_files`.
- `via`: target for matching traffic. Required (except on `default = true` rules, where it picks the fallthrough target).
- `fallback_via` / `fallback_direct` / `fallback_drop`: mutually exclusive; consulted when the primary `via` is a group that has zero healthy uplinks at dispatch time.
- `invert = true`: the rule matches addresses NOT in its prefix set. Applies to the CIDR side only and cannot be combined with `domains` (rejected at load — "not in this domain list" across the two address kinds is ambiguous; use a separate domain rule).
- `default = true`: exactly one rule must carry this; it matches everything not caught by the previous rules. The `default` rule must not set prefix or domain sources.

### Prefix matching

Internally each rule's inline + file prefixes are merged into a [`CidrSet`](src/routing/cidr.rs) — sorted `[start, end]` ranges (IPv4 as `u32`, IPv6 as `u128`) with overlapping and adjacent ranges merged. Lookup uses `partition_point` (binary search), O(log n) per rule.

### Hot-reload

Every rule with at least one `file` / `files` / `domain_files` entry gets a background tokio task that polls `mtime` of every listed path every `file_poll_secs` seconds. When any of them changes, the rule's CIDR and domain sets are rebuilt from the inline entries plus all reloaded files and swapped atomically (`Arc<RwLock<..>>`) — other rules and the table shape are unaffected. Parse or read errors on reload leave the previous sets in place and log a warning.

### Direct session idle timeout

`direct` connections are subject to a 2-minute bidirectional idle timeout. If no bytes flow in either direction for 120 seconds, both sockets are closed and FDs reclaimed. This prevents unbounded FD accumulation from clients that open TCP connections (e.g. DNS-over-HTTPS, DNS-over-TLS) and abandon them without sending FIN — leaving the server half open indefinitely. Any data activity in either direction resets the timer, so legitimate long-lived push-notification and keepalive connections are unaffected.

### Fallback semantics

When the primary `via` resolves to a group with no currently-healthy uplinks, the rule's fallback target is tried instead (one level, no recursion). Health is checked non-side-effectingly at dispatch time via `UplinkManager::has_any_healthy(transport)`; this is cheaper than building a candidate list and does not touch sticky-routes state. If the primary group recovers mid-session, future connections go through it normally — fallback is only consulted at dispatch.

### Group-level bypass (`bypass_when_down`)

Instead of declaring `fallback_direct = true` on every route, a group can opt into the bypass itself: with `bypass_when_down = true` on the `[[uplink_group]]`, traffic routed to the group dispatches `direct` while the group has no healthy uplink — including the implicit "everything to the default group" dispatch when no `[[route]]` is configured. An explicit route fallback still takes precedence; the bypass then applies (one level deep) to the group the fallback lands on. Like route fallbacks, the decision is re-evaluated live per dial/datagram/flow, so traffic returns to the tunnel as soon as any uplink recovers. On hosts where TUN holds the default route, set `direct_fwmark` so bypassed sockets escape the TUN routing loop. See "Bypass on a fully-down group" in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md) for details.

## Transport Modes

The six supported uplink shapes (native SS, SS/QUIC, SS/WS/H3, VLESS/QUIC, VLESS/WS/H3, VLESS/XHTTP/H3) are documented separately, with TOML examples and full dial-time fallback chains, in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md). The notes below cover only the operator-facing runtime details that aren't part of that reference.

Recommended operator stance:

- prefer `ws_h1` as a conservative baseline
- enable `ws_h2` only when the reverse proxy and origin are known-good for RFC 8441
- enable `ws_h3` only when QUIC is explicitly supported and reachable
- enable `xhttp_h2` / `xhttp_h3` when WebSocket Upgrade is blocked on the network path; the dispatcher falls through to `xhttp_h1` automatically when both QUIC and h2 ALPN are also blocked (the h1 step is throughput-limited but keeps the wire URL identical to xray)

**Shared QUIC endpoint:** H3 connections that do not use a per-uplink `fwmark` share a single UDP socket per address family (one for IPv4, one for IPv6). This means N warm-standby connections do not open N UDP sockets. Connections that require a specific `fwmark` still use their own dedicated socket because the mark must be applied before the first `sendmsg`.

QUIC keep-alive pings are sent every 10 seconds to prevent NAT mapping expiry and to allow the server to detect dead connections without waiting for the full idle timeout.

**Mode downgrade window:** the per-uplink window that gates re-attempts of an "advanced mode" (H3 / xhttp_h3) after a failure is configured by `h3_downgrade_secs` (default: 60s; also accepted as `mode_downgrade_secs`). Set to `0` to disable. The same window is also opened by TCP probe failures on H3 uplinks — without that, intermittent advanced-mode probe pass/fail alternation would cause a failover switch every probe cycle in `active_passive + global` mode. See [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md#downgrade-window-mechanics) for the two-layer (per-host cache + per-uplink window) breakdown.

Scoring during a downgrade window (`per_flow` scope):
- While the downgrade timer is active, the uplink's effective latency score has `failure_penalty_max` added on top of the normal failure penalty. This prevents `active_active + per_flow` flows from switching back to the primary uplink while it is operating in H2 fallback mode: as the normal failure penalty decays, the extra downgrade penalty keeps the primary's score unfavorable until the window closes.

Warm-standby connections respect the active downgrade state: while an uplink is in H3→H2 downgrade, new standby slots are filled using H2.

**Transport handshake timeouts:** every WebSocket connect path enforces an upper bound so that a silently-broken or black-holed server cannot stall new sessions for minutes while keeping the uplink nominally "healthy".

- **Fresh connect** (new TCP/QUIC + TLS + protocol handshake): 10 s for H1, H2, and H3. Without this bound a network black hole can hang up to ~127 s (Linux TCP SYN retransmit, H1/H2) or up to 120 s (QUIC `max_idle_timeout`, H3).
- **Reused shared H2/H3 connection** (opening a new WebSocket stream over an already-established connection): 7 s per await for H3, 10 s per await for H2. This catches the case where the shared pool handle is still nominally "open" to the client-side library but the underlying path has died — e.g. NAT rebinding, server graceful close received late, or silent packet loss.

When a timeout fires, the error is treated as an upstream runtime failure: the shared pool entry (if any) is invalidated on the next open attempt, `report_runtime_failure` sets a cooldown, and the probe is woken immediately. In `active_passive + global` mode the active uplink is replaced only after the probe confirms the primary as down on a fresh connect of its own — transient shared-pool glitches do not change the exit IP, while recovery when the primary is genuinely unreachable is bounded to roughly one probe cycle.

**Shared connection reconnect serialization:** when the shared H2 or H3 connection drops and N sessions simultaneously try to reconnect, only one new TCP+TLS+H2 or QUIC+TLS+H3 handshake is performed. A per-server-key `tokio::sync::Mutex<()>` serialises the slow path: the first waiter establishes the connection and caches it; all other waiters find the fresh entry under the lock and reuse it without starting their own handshake. This prevents thundering herd storms where N sessions each independently open a full TLS negotiation toward the same server after a shared connection drop.

**SOCKS5 negotiation abort classification:** when a local SOCKS5 client (TUN interceptor such as Sing-box or Clash) aborts the handshake early — closing the TCP connection after the method-negotiation greeting but before or during the CONNECT request — the resulting `early eof` / `failed to read request header` errors are classified as expected client disconnects and logged at `debug` level rather than `warn`. This is normal behaviour during reconnect storms when the TUN interceptor flushes its connection pool.

## Carrier Padding

Optional application-layer padding for the WebSocket / XHTTP dials — the client half of the server's `[padding]` feature. Each Shadowsocks chunk or VLESS frame is wrapped in a length-delimited `real_len | pad_len | real | pad` frame so the outer TLS record size no longer tracks the payload size, defeating the record-size correlation TLS-in-TLS classifiers key on.

- **Global default + per-uplink override.** The `[padding]` block sets the scheme parameters and a default on/off (`enabled`); each `[[outline.uplinks]]` may override it with `padding = true` / `padding = false`. The effective decision for a dial is the per-uplink value when set, else the global default (same override/fallback shape as the per-uplink `fingerprint_profile`). Leave the global default off and set `padding = true` on the uplinks pointing at your own padded servers; or leave it on and set `padding = false` on a VLESS uplink aimed at a third-party server (xray / sing-box) so it stays plain. A padded dial (SS and VLESS, TCP and UDP alike) must point at server path(s) that are also padded.
- **Config-synchronised, not negotiated.** The server must enable `[padding]` on the matching carrier path (`outline-ss-rust` `[padding] paths`) or the padded frames break its decoder. Off by default (wire unchanged).
- **Cover traffic.** With `cover = true` the uplink emits pad-only frames on an idle connection at a jittered interval (`cover_jitter_min_ms` … `cover_jitter_max_ms`).

Covers SS- and VLESS-over-WebSocket (h1/h2/h3) and -over-XHTTP alike, and UDP is padded per-datagram on every WS carrier — SS-UDP (split: list its path; combined: the shared base path) and VLESS-UDP both. Full reference: [`docs/PADDING.md`](../../docs/PADDING.md); the `[padding]` block in `config.toml` lists the knobs.

## Uplink Selection and Runtime Behavior

Each uplink has its own:

- TCP URL and mode
- UDP URL and mode
- cipher and password
- optional Linux `fwmark`
- per-uplink priority via `weight` — treated as a **hard** ordering signal: among healthy candidates the highest weight always wins, regardless of EWMA. Use `weight` to mark backups you do not want the failover/sticky path to drift onto. Equal-weight uplinks are tie-broken by EWMA-derived score (and finally by config index).

Selection pipeline:

1. Health probes update the latest raw RTT and EWMA RTT.
2. Probe-confirmed failures add a decaying failure penalty. When probes are enabled, runtime failures (e.g. an H3 connection reset under load) do not add a penalty on their own — they only set a temporary cooldown. The penalty is added only when a probe confirms a real failure (`consecutive_failures ≥ min_failures`). This prevents penalty accumulation on a healthy uplink due to transient errors under load.
3. Effective latency is derived from EWMA RTT plus current penalty.
4. Candidates are sorted: healthy first, then by `weight` (higher first), then by `effective_latency / weight`, then by config index. EWMA-derived score only ranks within the **same** weight band — it cannot promote a lower-weight uplink above a higher-weight one.
5. Sticky routing and hysteresis reduce avoidable switches.
6. Warm-standby pools reduce connection setup latency.

**Sticky-route cap:** the sticky-route table is bounded at 100,000 per-flow entries. Under traffic from large NAT pools or many distinct clients in `per_flow` routing scope, the table would otherwise grow unboundedly. New per-flow entries beyond the cap are silently dropped — the flow falls back to a fresh latency-ordered selection instead of a sticky one. Global and per-transport pinned entries (used in `global` and `per_uplink` scopes) are always stored regardless of this limit.

Routing scope behavior:

- `per_flow`: different targets can choose different uplinks
- `per_uplink`: one selected uplink is shared per transport, so TCP and UDP may still use different uplinks; in `active_passive` mode each transport keeps its own pinned active uplink until failover or explicit reselection, and penalties no longer bias the strict transport score
- `global`: one selected uplink is shared across all new user traffic until failover or explicit reselection. TCP score still takes priority for ranking, but UDP-capable active uplinks must also keep UDP healthy: a UDP probe failure or UDP runtime cooldown can trigger a global failover. Penalties no longer bias the strict global score.

**Auto-failback behavior:** controlled by `load_balancing.auto_failback` (default `false`).

- `false` (default): the active uplink is **only replaced when it fails** (enters cooldown or is no longer healthy). While the active uplink is still healthy, it stays active regardless of whether a higher-priority uplink has recovered. This is the recommended setting for production because it avoids connection disruption caused by proactive primary preference.
- `true`: when the current active uplink is healthy and a probe-healthy candidate with a higher `weight` (or equal weight and lower config index) exists, the proxy may return traffic to that candidate — but only after the candidate has accumulated `min_failures` consecutive successful probe cycles. Priority is determined by `weight`, not EWMA: this prevents spurious switches under load, when the active uplink's EWMA is temporarily elevated. Failback only moves toward higher weight; switching to a lower-weight uplink requires a probe-confirmed failover.

**Penalty-aware failover:** when the current active uplink enters cooldown and the selector must pick a replacement, candidates are re-sorted as: healthy first → cooldown remaining → `weight` (higher first) → penalty-aware EWMA score (`(EWMA + penalty) / weight`) → config index. `weight` is the primary ordering signal so a deliberately downranked backup is not promoted by a faster probe RTT alone; the penalty-aware score still breaks ties within the same weight, preventing oscillation with three or more equal-weight uplinks (without penalties a probe-cleared primary with a better raw EWMA would be selected again immediately even though it just failed).

Runtime failover:

- UDP can switch uplinks within an active association after runtime send/read failure.
- TCP can fail over before a usable tunnel is established.
- Established TCP tunnels are not live-migrated.

## Health Probes

Available probe types:

- `ws`: verifies TCP+TLS+WebSocket handshake connectivity to the uplink. No WebSocket ping/pong frames are sent — many servers do not respond to WebSocket ping control frames. Confirms that a new connection can be established; data-path integrity is verified by HTTP/DNS probes.
- `http`: real HTTP request over `websocket-stream` — verifies the full data path.
- `dns`: real DNS exchange over `websocket-packet` — verifies the full UDP data path.

Probe execution controls:

- `max_concurrent`: total concurrent probe tasks
- `max_dials`: dedicated cap for probe dial attempts
- `min_failures`: consecutive probe failures required before the uplink is marked unhealthy (default: `1`). Also used as the consecutive-success threshold for auto-failback stability: when `auto_failback = true`, a recovered primary must accumulate `min_failures` consecutive probe successes before traffic can be returned to it.
- `attempts`: number of probe attempts per uplink per cycle. Each attempt that fails increments the consecutive-failure counter; a passing attempt resets it to zero and increments the consecutive-success counter.
- `endpoint_check` (default `false`): bare-TCP reachability pre-check across every endpoint of the uplink (primary + fallbacks, both planes, deduplicated by `host:port` plus egress options), run concurrently before the carrier/application probes. After `min_failures` cycles in which **no** endpoint accepts a connect, the uplink is marked unhealthy immediately — no carrier descent, no wire-by-wire walk — with the endpoint list surfaced in `last_error`. This is what turns "host switched off" from a multi-minute discovery (`h3 → h2 → h1` on every wire, each step paying the full `timeout`) into a couple of cycles. A reachable endpoint asserts nothing: the regular probe still owns health. Leave it off when an endpoint serves QUIC/H3 on UDP with the matching TCP port closed — the check would read that as "server gone".
- `endpoint_check_timeout_ms` (default `2000`): per-endpoint deadline for `endpoint_check`, resolution included. Keep it well under `timeout_secs`: a dead host costs the full deadline every cycle, since a blackholed SYN never draws an RST. Outcomes are recorded as `probe="endpoint"` in `outline_ws_probe_runs_total` / `outline_ws_probe_duration_seconds`.

Probe timing:

- Probes normally run on a fixed `interval` timer.
- When a runtime failure sets a fresh failure cooldown on an uplink, the probe loop is immediately woken up (via an internal `Notify`) so that failover is confirmed within one probe cycle rather than waiting for the next scheduled interval. This significantly reduces end-to-end failover latency.
- **Probe suppression under active traffic (global + probe):** in `routing_scope = global` mode with probes enabled, the probe cycle is skipped for an uplink when all three conditions are met: (1) real traffic was observed within the last `interval`, (2) the uplink is probe-healthy (`tcp_healthy = true`), (3) routing scope is `global`. Active traffic is stronger evidence of reachability than a probe ping. This prevents false-negative probe results under load: when the probe loop wakes immediately after an H3 runtime failure, the server may be busy and unable to accept a new QUIC connection for the probe — which would otherwise cause a spurious failover. For non-global scopes the probe still runs even when traffic is active, to confirm recovery after cooldown.

Warm-standby validation:

- Every 15 seconds, standby connections are validated using a 1 ms non-blocking read. If the server closed the connection (EOF, close frame, or error), the slot is cleared and refilled. A timeout (no data in 1 ms) means the connection is still open.

Probe activation rules:

- probes do not start unless probe settings are explicitly configured
- `[probe]` alone does not enable any check
- at least one of `[probe.ws]`, `[probe.http]`, `[probe.dns]`, `[probe.tcp]`, or `[probe.tls]` must be present

Uplinks without a `udp_ws_url` are treated as TCP-only: UDP health state and standby slots are not created or tracked for them, and UDP-related probe outcomes do not affect their UDP health metric.

## IPv6

Supported:

- SOCKS5 IPv6 targets
- IPv6 literal upstream URLs such as `wss://[2001:db8::10]/SECRET/tcp`
- IPv6 probes
- IPv6 listeners
- IPv6 UDP packets in TUN mode
- IPv6 upstream transport for `h2` and `h3`

## TUN Mode

The process attaches only to an already existing TUN device. Interface creation, addresses, routing, and policy routing stay outside the app.

### tun2udp

Capabilities:

- IPv4 and IPv6 UDP packet forwarding
- IPv4 and IPv6 IP fragment reassembly on the TUN ingress path
- local IPv4 ICMP echo reply (`ping`) handling
- local IPv6 ICMPv6 echo reply handling, with source fragmentation to the IPv6 minimum MTU when needed
- optional group-health gating of those echo replies (`tun_suppress_icmp_reply_when_down` on the uplink group): pings routed to a group stop being answered while the group has no healthy uplink, so an external watchdog can detect a dead tunnel
- that gate also demands the health verdict be *fresh* (`tun_icmp_liveness_window_secs`). The reply is generated locally — the ping never leaves the host — so answering it only proves this loop ran, and `healthy` is sticky: a daemon whose probe loop has died keeps its last verdict forever and would go on answering while carrying no traffic. With the window, some healthy uplink must also have seen real traffic or completed a probe cycle inside it; otherwise the reply is withheld and counted as `icmp_reply_suppressed_stale`. Unset derives the window from the probe schedule (`max(3 × interval, liveness_interval + 60s, 60s)`); `0` restores the health-flag-only behaviour, and the freshness half is skipped entirely for a group with no probes configured
- IPv6 UDP and ICMPv6 handling across supported extension-header paths
- per-flow uplink transport
- flow idle cleanup
- bounded flow count
- oldest-flow eviction on overflow
- flow metrics and packet outcome metrics, including local ICMP replies

### tun2tcp

Capabilities:

- stateful userspace TCP relay over Outline TCP uplinks
- SYN / SYN-ACK / FIN / RST handling
- out-of-order buffering
- receive-window enforcement
- SACK-aware receive/send logic
- adaptive RTO
- zero-window persist/backoff
- bounded buffering and retransmit budgets
- flow termination on timeout, overflow, or relay failure
- transport-error reporting to the uplink penalty system: abrupt upstream closes (e.g. QUIC `APPLICATION_CLOSE` / `H3_INTERNAL_ERROR`) are forwarded to `report_runtime_failure`, so the H3→H2 downgrade and failure penalty apply to TUN TCP flows the same way they apply to SOCKS5 flows; clean WebSocket closes (FIN or Close frame) are not counted as failures

This is intended for real operations, but it is still not equivalent to a kernel TCP stack.

### IKE / IPsec NAT-T bypass

`tun.ipsec_bypass = true` adds a hard-coded fast-path: UDP flows whose destination port is **500** or **4500** skip policy routing and resolve to the direct path (same as `via = "direct"`). VoWiFi and other IKEv2/IPsec clients can then establish ESP-in-UDP datagrams that would otherwise be lost — the TUN classifier only forwards TCP/UDP/ICMP, so raw ESP (IP protocol 50) is always dropped regardless of the routing decision.

The bypass relies on the direct path's local socket to reach the destination. On hosts where TUN catches the default route, that socket would loop straight back into TUN; on Linux set `direct_fwmark` and add a matching `ip rule fwmark X lookup Y` so the bypassed flow escapes the loop. Without `direct_fwmark` and a corresponding policy-routing rule, the process logs a startup warning.

Default: `false`. Both ports must be matched together — IKEv2 stacks move IKE_AUTH off port 500 mid-session via NAT_DETECTION, so bypassing only 4500 still breaks the handshake.

### Carrier migration (surviving a dead carrier)

A tunnelled TUN flow does not own its transport: it shares one **carrier** — a single H3/H2/H1 connection — with every other flow on that uplink. When the carrier collapses (an H3 connection-level error takes down everything multiplexed on it at once), every flow riding it loses its transport in the same instant, and each application sees its connection die.

The upstream sockets, however, are not gone. The server moves each one into its orphan registry, keyed by the Session ID it minted for that flow, and holds it for 30 s ([`docs/SESSION-RESUMPTION.md`](../outline-ss-rust/docs/SESSION-RESUMPTION.md)). With `[tun.tcp] carrier_migration = true` (the default) a flow whose carrier dies re-dials a fresh one, presents **its own** Session ID, gets the parked upstream re-attached, and closes the byte gap in both directions before resuming: the **Ack-Prefix Protocol (v1)** tells it exactly how many uplink bytes the server actually forwarded, so it replays only the tail that was lost in flight, and **Symmetric Downlink Replay (v2)** hands back the downstream bytes the dead carrier never delivered, which are flushed to the application ahead of anything the new carrier produces. The application observes no disconnect — no FIN, no RST, no gap, no duplicate byte.

**It engages only on a confirmed resume hit.** A redial that presents an id can miss — the park expired, or the server has resumption off — and on a miss the server opens a *fresh* upstream to the destination, starting the byte stream from zero. Continuing a flow on that would splice a brand-new stream onto a half-finished one and hand the application a corrupt result that looks like success. So the client migrates only when the server *proves* the re-attach by emitting the v1 control frame (which it emits only after the orphan-take succeeded — the capability header on the upgrade response is not proof, since the server echoes it hit or miss). Everything else — a miss, a timeout, an unparseable frame, a replay the client can no longer reproduce byte-exact, a truncated downstream slice — falls through to the ordinary teardown, unchanged.

Consequences worth knowing:

- **Server-side resumption is off by default**, and a server without it never issues a Session ID — so those flows are never even eligible, and the knob costs nothing there. Turn on the server's `[resumption]` to get any of this.
- **Direct (`via = "direct"`) flows never migrate**: they own a plain socket to the origin, so there is no carrier to migrate off and nothing parked to re-attach.
- Bounded: at most **2 attempts per flow**, none started more than 20 s after the first (the server's park TTL is 30 s), and the uplink replay ring is capped at 64 KiB per flow — a flow that sends a single chunk larger than that loses its ring, and with it the ability to prove byte-exactness, so it tears down as before rather than resuming with a hole.
- **The migration dial asks for the uplink's configured carrier, not the capped one.** The carrier death that triggers a migration is itself reported as a runtime failure, which caps the uplink one rank down (`ws_h3` → `ws_h2`) for `mode_downgrade_secs`. Honouring that cap would hand every rescued flow the TCP-over-TCP carrier and it would keep it for life — nothing migrates a live flow back up — so a long download rescued from a dead H3 carrier would crawl where it used to reset and reconnect at full speed. The dial still falls back `h3 → h2 → h1` on its own when the carrier is genuinely broken, so ignoring the cap costs nothing when the cap was right. (Same reason the migration re-dials its own uplink rather than a re-selected one: the death may have put that uplink in cooldown.)
- Observable on `outline_ws_rust_tun_tcp_events_total{event=…}`: `carrier_migrated`, `carrier_migration_miss`, `carrier_migration_dial_failed`, `carrier_migration_replay_failed`.

Set `carrier_migration = false` to restore the pre-migration behaviour (a dead carrier becomes a FIN/RST immediately).

### TUN PMTUD safety gate

When the upstream transport refuses an oversize UDP datagram on the TUN path (SS-UDP, VLESS-UDP, SS-2022, …), the engine synthesises an ICMP "Fragmentation Needed" (IPv4) or "Packet Too Big" (IPv6) toward the original sender so its PMTUD state machine can react. The boolean knob `tun.pmtud_emit_below_quic_initial` controls a single question: **may that PTB advertise a path MTU below QUIC v1's Initial-datagram minimum (1200 v4 / 1280 v6, RFC 9000 §14.1)?**

Default `false` — sub-minimum PTBs are suppressed. Compliant QUIC stacks treat such a PTB as "destination cannot carry QUIC" and fall back to TCP, so leaving the gate in place keeps real QUIC traffic (YouTube, Google services) on UDP even when the TUN uplink's per-datagram budget sits just below 1200 bytes. Sub-minimum oversize drops are silently absorbed and the sender's own retransmit / timeout logic eventually adjusts.

Set `tun.pmtud_emit_below_quic_initial = true` to restore unconditional PTB emission. Use it on deployments where QUIC eviction is a non-issue and the explicit PMTUD signal on every sub-minimum drop is worth more — for example a pure VoWiFi / IKEv2 concentrator carrying IKE_AUTH with certificates over a narrow tunnel uplink, where the PTB is the only way for the IKE retransmit loop to learn the effective tunnel MTU. The full contract — when the PTB fires, what is throttled, where the minimum comes from, what changes on opt-in — lives in [docs/TUN-PMTUD.md](docs/TUN-PMTUD.md).

## Linux fwmark

Per-uplink `fwmark` applies `SO_MARK` to outbound sockets:

- HTTP/1.1 WebSocket TCP sockets
- HTTP/2 WebSocket TCP sockets
- HTTP/3 QUIC UDP sockets
- probe dials
- warm-standby connections

Requirements:

- Linux only
- `CAP_NET_ADMIN`
- under systemd, `PrivateUsers=no`: `setsockopt(SO_MARK)` is authorized against
  the network stack's owning (init) user namespace, so with `PrivateUsers=true`
  the capability applies only inside the private userns and every marked dial
  fails `EPERM` — `CAP_NET_ADMIN` alone is not enough. This applies to both
  per-uplink `fwmark` and top-level `direct_fwmark`.

## Metrics and Dashboards

If `[metrics]` is configured the process serves the read-only Prometheus
endpoint:

- `/metrics` - Prometheus text exposition

```bash
curl http://[::1]:9090/metrics
```

The metrics listener has **no** mutating endpoints. The earlier `/switch`
handler has been moved to a separate, authenticated control-plane listener
(see below) so observability access does not also grant authority to flip the
active uplink.

## Control plane

If `[control]` is configured the process serves mutating endpoints on a
**separate** TCP listener, gated by a mandatory bearer token:

- `GET /control/topology` - instance/group/uplink topology for dashboards
- `GET /control/summary` - compact group/uplink health counters
- `POST /control/activate` - JSON activation API for UI click actions
- `POST /control/uplink_enabled` - administratively enable/disable an uplink (operator on/off). JSON body `{"group":"main","uplink":"backup","enabled":false}`. A disabled uplink is removed from **all** automatic machinery — probing, candidate selection, failover, and warm-standby refill — until re-enabled; if it was the active uplink, traffic fails over to an enabled standby immediately. Runtime-only: the override is **not** persisted, so a process restart starts every uplink enabled. Exposed in the dashboard as the per-uplink On/Off button.
- `GET`/`POST`/`PATCH`/`DELETE /control/uplinks` - stage `[[outline.uplinks]]` edits in the config file
- `POST /control/apply` - hot-apply staged uplink edits without a process restart
- `POST /switch` - manual active-uplink override

There is no anonymous access path. Requests without a matching
`Authorization: Bearer <token>` header are rejected with `401 Unauthorized`
before the request body is inspected.

### Configuration

Either configure both `listen` and a token in `[control]`, or pass
`--control-listen` (`CONTROL_LISTEN`) together with `--control-token`
(`CONTROL_TOKEN`). The token may also be read from a sidecar file via
`token_file = "..."` (path resolved relative to the config file). Setting
only one of the two halves is a startup error.

Bind the control listener to loopback or a management VLAN; the token is
defence in depth, not a substitute for network-level isolation.

### Manual uplink switch

`POST /switch` lets an operator pin the active uplink for an `active_passive`
group without waiting for the probe loop. The selection is persisted via the
state store (when configured) so it survives restarts.

Query parameters:

- `uplink` (required) - uplink name to activate.
- `group` (optional) - target group. When omitted, the registry searches all
  groups (uplink names are globally unique).
- `transport` (optional) - `tcp`, `udp`, or `both` (default). Honoured only in
  `routing_scope = per_uplink`; ignored under `global` scope.

Examples:

```bash
TOKEN="long-random-secret"

# Switch the only group to uplink "backup" (both transports if per_uplink)
curl -XPOST -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/switch?uplink=backup'

# Switch only the UDP active uplink in per_uplink mode
curl -XPOST -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/switch?uplink=backup&transport=udp'

# Disambiguate by group name
curl -XPOST -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/switch?group=main&uplink=backup'
```

Returns `200` on success, `400` when the uplink/group is unknown or the group
is not in `active_passive` mode, `401` when the bearer token is missing or
incorrect, and `405` for non-POST methods. The override holds while the
chosen uplink is healthy; if the probe loop later marks it unhealthy, normal
failover takes over. With `auto_failback = true`, the loop may flip back to a
higher-priority uplink once it stabilises.

### Dashboard-oriented control APIs

`GET /control/topology` returns JSON with groups and uplinks (including
`active_global`, `active_tcp`, `active_udp` booleans per uplink) for the
built-in dashboard or external control clients.

`GET /control/summary` returns compact counters:
`groups_total`, `uplinks_total`, healthy/unhealthy TCP/UDP counts, and active
selection counters.

`POST /control/activate` accepts JSON and reuses the same internal switching
logic as `/switch`:

```json
{
  "group": "core",
  "uplink": "uplink-02",
  "transport": "tcp"
}
```

`/control/uplinks` mutates the canonical `[[outline.uplinks]]` array in the
on-disk TOML. Mutation responses include `apply_required: true` when
`/control/apply` can activate the staged change; `restart_required` is reserved
for control states that cannot hot-apply.

Examples:

```bash
TOKEN="long-random-secret"

curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/control/topology'

curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:9091/control/summary'

curl -XPOST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group":"core","uplink":"uplink-02","transport":"tcp"}' \
  'http://127.0.0.1:9091/control/activate'
```

Prometheus example:

```yaml
scrape_configs:
  - job_name: outline-ws-rust
    metrics_path: /metrics
    static_configs:
      - targets:
          - "[::1]:9090"
```

Metrics include:

- build and startup info
- process resident memory and heap usage gauges
- SOCKS5 requests and active sessions, including `command="connect"`, `command="udp_associate"`, and `command="udp_in_tcp"`
- session duration histogram
- payload bytes and UDP datagrams
- oversized UDP drop counters for incoming client packets and outgoing client responses
- uplink health, latency, EWMA RTT, penalties, score, cooldown, standby readiness. `uplink_health` is exported as `1` (healthy) or `0` (unhealthy) only when the probe has run and confirmed a state. Before the first probe cycle the metric is absent — an empty value means "unknown", not unhealthy.
- routing policy and active-uplink selection state
- probe results and latency
- warm-standby acquire and refill outcomes
- TUN flow and packet metrics
- `tun2tcp` retransmit, backlog, window, RTT, and RTO metrics

On Linux, the process memory sampler updates:

- `outline_ws_process_resident_memory_bytes`
- `outline_ws_process_virtual_memory_bytes`
- `outline_ws_process_heap_allocated_bytes`
- `outline_ws_process_heap_mode_info{mode}`
- `outline_ws_process_open_fds`
- `outline_ws_process_threads`

Heap metrics currently fall back to `VmData`-based estimation on Linux and export `heap_mode_info{mode="estimated"}`.

On Linux, the process also emits a periodic descriptor inventory log:

- `process fd snapshot`

The descriptor snapshot includes total open FDs plus a breakdown for sockets, pipes, anon inodes, regular files, and other descriptor types.

`outline_ws_selection_mode_info{mode}`, `outline_ws_routing_scope_info{scope}`, `outline_ws_global_active_uplink_info{uplink}`, and `outline_ws_sticky_routes` expose selector configuration and active-uplink state.

`outline_ws_group_bypass_active{group, transport}` reports the live `bypass_when_down` state: `1` while new flows of that transport are being dispatched direct (tunnel bypass) because the group has no healthy uplink, `0` while traffic tunnels normally. The series exists only for groups with `bypass_when_down = true`; the built-in dashboard renders the same signal as a group-header chip (grey `Bypass: armed` / amber `Bypass: DIRECT`), and the Grafana dashboard carries a matching stat + timeline in the Routing Policy section.

Per-uplink open-connection accounting (used to detect connections leaking
into a non-active uplink after a `Global` / `PerUplink` switchover) is
exported by:

- `outline_ws_uplink_open_connections{group, transport, uplink}` — gauge
  of currently open upstream transports attributed to each uplink. After a
  switchover the new active uplink ramps up while the old one drains; a
  series that fails to drain is the leak signal.
- `outline_ws_uplink_connection_close_total{group, transport, uplink, classification}`
  — counter of upstream-transport closes, classified at close time as
  `active` (the uplink was still active), `inactive` (the active pointer
  had moved elsewhere — a stranded session draining), or `unknown`
  (`PerFlow` scope where no active pointer exists).
  `rate(...{classification="inactive"}[5m])` is the drain rate after a
  switchover; sustained non-zero outside a recent switch points at a stale
  sticky route or warm-standby pool.

Both are wired to the dashboard row `Inactive Uplink Leak (Global / Per-Uplink)`
in `grafana/outline-ws-rust-dashboard.json`. Probe / health-check
connections are intentionally *not* attributed — the metrics cover only
user-traffic dials.
When TUN UDP forwarding fails before a packet can be delivered upstream, `outline_ws_tun_udp_forward_errors_total{reason}` breaks that down into `all_uplinks_failed`, `transport_error`, `connect_failed`, and `other`.
Oversized SOCKS5 UDP packets dropped before uplink forwarding, and oversized UDP responses dropped before client delivery, are exported as `outline_ws_udp_oversized_dropped_total{direction="incoming|outgoing", cause}` (the `cause` label distinguishes `quic_dgram`, `vless_quic_dgram`, `vless_udp`, `ss_socket`, `socks_client`, `socks_relay`, `socks_direct`, `socks_in_tcp`).
On the TUN UDP path, oversize drops also synthesise an ICMP "Fragmentation Needed" (IPv4) or "Packet Too Big" (IPv6) reply toward the sender so its own PMTUD state machine can react — throttled to one PTB per second per flow, and suppressed below QUIC v1's Initial-datagram floor (1200 v4 / 1280 v6) so well-behaved QUIC clients are not pushed off UDP into a TCP fallback. See [docs/TUN-PMTUD.md](docs/TUN-PMTUD.md) for the full contract.
Local ICMP echo handling is exported separately via `outline_ws_tun_icmp_local_replies_total{ip_family}`.

Grafana dashboards:

- [`grafana/outline-ws-rust-dashboard.json`](grafana/outline-ws-rust-dashboard.json)
- [`grafana/outline-ws-rust-hang-diagnostics.json`](grafana/outline-ws-rust-hang-diagnostics.json)

The experimental uplinks/control-plane Grafana dashboard is intentionally not packaged; use the built-in `/dashboard` UI for multi-instance uplink activation.

## Production Operations

### `install-client.sh`

For a basic production install on Linux use the bundled [install-client.sh](../../install-client.sh) script. Run it as `root` on the target host:

```bash
curl -fsSL https://raw.githubusercontent.com/balookrd/outline-proxy/main/install-client.sh -o install-client.sh
chmod +x install-client.sh
./install-client.sh --help
sudo ./install-client.sh
```

Install modes:

- Default: installs the latest stable release for the current architecture
- `CHANNEL=nightly`: installs the rolling nightly prerelease
- `VERSION=v1.2.3`: pins the install to a specific stable tag

Examples:

```bash
./install-client.sh --help
sudo ./install-client.sh
sudo ./install-client.sh --force
sudo CHANNEL=nightly ./install-client.sh
sudo VERSION=v1.2.3 ./install-client.sh
sudo ./install-client.sh --remove
sudo ./install-client.sh --purge
```

What the script does:

- detects the host architecture and downloads the latest GitHub release artifact
- skips the download if the installed version already matches the selected release; use `--force` or `FORCE=1` to override
- for the nightly channel, tracks the release commit SHA in `/var/lib/outline-ws-rust/nightly-commit` to detect new builds
- installs the binary to `/usr/local/bin/outline-ws-rust`
- installs unit files into `/etc/systemd/system`
- creates `/etc/outline-ws-rust` and `/var/lib/outline-ws-rust`
- downloads `config.toml` and `instances/example.toml` only if they do not already exist
- restarts only already-active `outline-ws-rust` units
- does not automatically enable/start a fresh service

After the first install:

1. Edit `/etc/outline-ws-rust/config.toml`.
2. Enable one of the service variants:
   - single instance: `sudo systemctl enable --now outline-ws-rust.service`
   - named instance: `sudo systemctl enable --now outline-ws-rust@NAME.service`
3. Check status with `systemctl status outline-ws-rust --no-pager`.
4. Check logs with `journalctl -u outline-ws-rust -e --no-pager`.

The script is safe to re-run for upgrades: it compares the installed version against the selected release and only downloads and replaces the binary when a newer version is available. It automatically restarts any active `outline-ws-rust` units after upgrade. If the service was stopped, the script leaves it stopped.

Supported release architectures currently match GitHub CI artifacts: `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.

Useful overrides:

- `CHANNEL=stable|nightly`: choose the release channel; default is `stable`
- `VERSION=v1.2.3`: pin the install to a specific stable tag
- `FORCE=1`: reinstall even when the installed version already matches
- `INSTALL_PATH=/path`: install the binary outside `/usr/local/bin`
- `CONFIG_DIR=/path`: keep configuration outside `/etc/outline-ws-rust`
- `STATE_DIR=/path`: use a different state directory
- `GITHUB_TOKEN=...`: GitHub token to avoid API rate limits

`VERSION` and `CHANNEL=nightly` are mutually exclusive.

Removal:

```bash
sudo ./install-client.sh --remove   # stop+disable every unit, drop unit files, binary and backups
sudo ./install-client.sh --purge    # also delete config, state dir and the service user/group
```

- `--remove` (alias `--uninstall`): stops and disables the main `outline-ws-rust.service` **and every** `outline-ws-rust@NAME.service` instance, removes both unit files (plain + template, followed by `daemon-reload`), the binary and its `.bak.*` backups. Keeps `/etc/outline-ws-rust` (including `instances/`), `/var/lib/outline-ws-rust` and the `outline-ws` user/group, so a later reinstall reuses the existing config.
- `--purge`: everything `--remove` does, plus deletes `/etc/outline-ws-rust`, `/var/lib/outline-ws-rust` and the `outline-ws` user/group — a complete uninstall. Both modes are idempotent: missing artifacts are skipped, not treated as errors.

#### Installing through an HTTP(S) proxy

If `github.com` or its release CDN (`objects.githubusercontent.com`) is unreachable from the host, route the install through any HTTP/SOCKS5 proxy that can reach GitHub. The script does not need to be modified — `curl` honours the standard proxy environment variables.

Important: `sudo` strips `http_proxy`/`https_proxy` from the environment by default, so pass them explicitly:

```bash
sudo https_proxy=http://HOST:PORT http_proxy=http://HOST:PORT ./install-client.sh
```

or export and use `sudo -E`:

```bash
export https_proxy=http://HOST:PORT
export http_proxy=http://HOST:PORT
sudo -E ./install-client.sh
```

For SOCKS5 (e.g. an `ssh -D 1080 user@vps` tunnel) use `ALL_PROXY=socks5h://HOST:PORT`. Authenticated proxies use `http://USER:PASS@HOST:PORT` (URL-encode special characters in the password).

Verify the proxy works before running the installer:

```bash
curl -v --proxy http://HOST:PORT --max-time 20 https://github.com -o /dev/null
```

### systemd

Production-oriented systemd units are included at:

- [`systemd/outline-ws-rust.service`](systemd/outline-ws-rust.service) — single instance
- [`systemd/outline-ws-rust@.service`](systemd/outline-ws-rust@.service) — named-instance template (reads config from `instances/NAME.toml`)

Typical installation flow:

1. Install the binary to `/usr/local/bin/outline-ws-rust`.
2. Install the configuration to `/etc/outline-ws-rust/config.toml`.
3. Copy both unit files to `/etc/systemd/system/`.
4. Reload and enable the service:
   `sudo systemctl daemon-reload && sudo systemctl enable --now outline-ws-rust`

The unit includes:

- automatic restart on failure
- journald logging
- elevated `LimitNOFILE`
- `LimitSTACK=8M` to avoid oversized anonymous thread-stack reservations
- a fixed `outline-ws` system user / group (provisioned by `install-client.sh`) so state files keep a stable owner across restarts and `StateDirectory=outline-ws-rust/_default` lands on a writable, unit-managed path
- `CAP_NET_ADMIN` for `fwmark`; remove if `fwmark` is not used. Using `fwmark` / `direct_fwmark` also requires `PrivateUsers=no` (a drop-in override) — `SO_MARK` fails `EPERM` inside the default private user namespace even with the capability held
- `PrivateDevices=false` — required for TUN mode; harmless if TUN is not used
- conservative systemd hardening flags

On Linux, the bundled runtime pins Tokio worker and blocking thread stacks to 2 MiB so the process does not inherit very large per-thread virtual stack mappings from the host environment.

### Logging

The service uses `tracing` for structured logs. The bundled systemd unit sets:

```text
RUST_LOG=info
```

Use `debug` only during troubleshooting — connection lifecycle and transport-layer events become much more verbose.

### Security Notes

- Protect `metrics.listen`; do not expose it without additional access controls.
- Protect `control.listen` even more strictly: bind it to loopback or a
  management network, treat the bearer token as a credential (rotate, store
  out of band), and never re-use the metrics port for it. The control listener
  is the only path that can mutate active-uplink selection.
- Listener hardening against slowloris / idle-connection DoS is built in:
  the SOCKS5 accept loop caps in-flight connections at 4096 and enforces a
  10 s handshake timeout on `negotiate`; the `/metrics` listener caps
  concurrency at 64 with a 5 s header-read timeout; the control listener
  caps concurrency at 16 with the same 5 s header-read timeout (the bearer
  check runs only after headers are received, so the timeout is what keeps
  unauthenticated peers from pinning sockets). These ceilings are compiled
  in and not config-tunable.
- HTTP/3 requires public UDP reachability on the selected port.
- `fwmark` works only on Linux and requires `CAP_NET_ADMIN` or root; under a user-namespaced systemd sandbox it additionally requires `PrivateUsers=no` (`SO_MARK` is checked against the init user namespace).
- TUN mode requires `/dev/net/tun` access on the host (`PrivateDevices=false`).

## Testing

Useful local checks:

```bash
cargo check
cargo test
```

Manual real-upstream integration tests exist for HTTP/2 and HTTP/3:

```bash
RUN_REAL_SERVER_H2=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test --test real_server_h2 -- --nocapture
```

```bash
RUN_REAL_SERVER_H3=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test --test real_server_h3 -- --nocapture
```

Integration tests for group isolation, fallback, and direct dispatch:

```bash
cargo test --test group_routing -- --nocapture
```

Warm-standby integration test:

```bash
cargo test --test standby_validation -- --nocapture
```

## Protocol References

- [Outline `outline-ss-server`](https://github.com/Jigsaw-Code/outline-ss-server)
- [`hev-socks5-core`](https://github.com/heiher/hev-socks5-core)
- [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel)
- [Shadowsocks AEAD specification](https://shadowsocks.org/doc/aead.html)
- [RFC 8441: Bootstrapping WebSockets with HTTP/2](https://datatracker.ietf.org/doc/html/rfc8441)
- [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://datatracker.ietf.org/doc/html/rfc9220)

## Local Patch Tracking

Vendored dependency patches are tracked in:

- [`PATCHES.md`](PATCHES.md)

This is the source of truth for local deviations from upstream crates, including the vendored `h3` patch used for RFC 9220 support.
