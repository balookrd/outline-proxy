<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img src="docs/logo-light.png" alt="outline-proxy logo" width="100%">
  </picture>
</p>

# outline-ws-rust

`outline-ws-rust` is the client binary of the `outline-proxy` monorepo. It accepts local SOCKS5 traffic and, optionally, packets from an existing TUN device, and forwards them to an `outline-ss-rust` server (or another Outline-compatible / VLESS server) over WebSocket on HTTP/1.1, HTTP/2 or HTTP/3, or over XHTTP on the same three HTTP versions.

This document covers building, configuring and running the client on Linux. Operating the server side is described in [`bins/outline-ss-rust/README.md`](../outline-ss-rust/README.md); the per-shape uplink reference is [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md).

It supports:

- SOCKS5 `CONNECT`
- SOCKS5 `UDP ASSOCIATE` and `hev-socks5` `UDP-in-TCP` (`CMD=0x05`)
- several uplinks with failover and load balancing
- WebSocket over HTTP/1.1, RFC 8441 (`ws-over-h2`) and RFC 9220 (`ws-over-h3`)
- XHTTP (`xhttp_h1` / `xhttp_h2` / `xhttp_h3`) for Shadowsocks and VLESS
- VLESS uplinks (UUID auth, per-destination UDP session-mux)
- one-line uplink config from a `vless://…` or `ss://…` share-link URI (TOML `link = "..."`, CLI `--vless-link`, control-plane `link` payload field)
- Prometheus metrics and Grafana dashboards; the multi-instance operator UI is the separate `outline-ui` service
- an existing TUN device: `tun2udp` and a userspace `tun2tcp` relay

---

*Русская версия: [README.ru.md](README.ru.md)*

## What the process does

1. Accepts local SOCKS5 and optional TUN traffic.
2. Selects an uplink using health probes, EWMA RTT scoring, sticky routing, hysteresis, failure penalties and warm standby.
3. Dials the uplink in the configured carrier mode (`ws_h1` / `ws_h2` / `ws_h3` or `xhttp_h1` / `xhttp_h2` / `xhttp_h3`) and falls back to a lower HTTP version when the dial fails.
4. Encrypts payloads with Shadowsocks AEAD, or frames them as VLESS with UUID auth, before sending them upstream.
5. Exports Prometheus metrics for runtime, uplinks, probes, TUN and `tun2tcp`.

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
        GD["Grafana dashboards"]
        AL["Alert rules"]
    end

    M --> PR
    PR --> GD
    PR --> AL
```

## Supported features

### SOCKS5

- no-auth SOCKS5
- optional username/password auth (RFC 1929)
- TCP `CONNECT`
- UDP `ASSOCIATE`
- `hev-socks5` `FWD UDP` / `UDP-in-TCP` (`CMD=0x05`)
- pipelined SOCKS5 handshake from `hev-socks5-tunnel`
- reassembly of fragmented SOCKS5 UDP datagrams from the client
- IPv4, IPv6 and domain-name targets
- policy routing by destination CIDR or domain suffix, with file-backed lists reloaded on mtime change, per-rule fallback (`fallback_via` / `fallback_direct` / `fallback_drop`) and the built-in targets `direct` and `drop`
- group-level tunnel bypass (`bypass_when_down` on the uplink group): while a group has no healthy uplink, traffic routed to it goes `direct` instead of failing, and returns to the tunnel as soon as any uplink recovers

### Outline transports

- `ws://` and `wss://`
- HTTP/1.1 Upgrade
- RFC 8441 WebSocket over HTTP/2
- RFC 9220 WebSocket over HTTP/3 / QUIC
- XHTTP (`xhttp_h1` / `xhttp_h2` / `xhttp_h3`) for SS (`tcp_xhttp_url` / `udp_xhttp_url`) and VLESS (`vless_xhttp_url`); pairs with the XHTTP endpoints of outline-ss-rust. The query string of the dial URL selects the submode: a bare URL or `?mode=packet-up` runs a GET plus sequenced POSTs, `?mode=stream-one` runs one bidirectional POST (h2 / h3 only; the h1 carrier supports packet-up only and fails on stream-one). Use it when WebSocket upgrades are blocked on the path (CDNs, captive-portal middleboxes).
- VLESS uplinks (`transport = "vless"`, UUID auth, per-destination UDP session-mux bounded by `vless_udp_max_sessions`)
- carrier fallback on dial failure:
  - `ws_h3 -> ws_h2 -> ws_h1`
  - `ws_h2 -> ws_h1`
  - `xhttp_h3 -> xhttp_h2 -> xhttp_h1` (packet-up only; stream-one stops at h2). The same `X-Outline-Resume` token is carried across each carrier switch, so an outline-ss-rust server with session resumption enabled re-attaches the parked upstream instead of opening a new one. The h1 step is for paths that block both QUIC and the h2 ALPN; it opens two keep-alive sockets per session (long-lived GET + serialised POSTs) because h1 cannot multiplex.
  - per-uplink fallback wires via `[[outline.uplinks.fallbacks]]`: each uplink may declare further wire shapes (another `transport` + URL) that the dial loop tries when the primary fails on this uplink, e.g. `vless → ss` or `ss → vless`. After `probe.min_failures` consecutive dial failures the active wire stays on the fallback for `mode_downgrade_secs` and new sessions start there; when that pin expires, sessions return to the primary. Resume tokens (`X-Outline-Resume`) survive the wire switch through the identity-level resume cache, so a resume-enabled server re-attaches the upstream across `vless ↔ ss`. The chunk-0 failover loop tries every other wire of the same uplink before moving to another uplink. `shuffle_wires = true` shuffles the chain at process start (collision-free permutations within an `[[uplink_group]]`) and hands over to uplink failover after one full pass without a successful wire (any successful wire resets the pass); `shuffle_timer = "1h"` rerolls `active_wire` on a per-uplink interval (`30s` / `5m` / `1h30m` / `2d` / bare seconds) and suppresses probe-driven early failback to the primary so the reroll stays in effect. `carrier_downgrade = false` disables the carrier cascade inside a wire, so a failure moves straight to the next wire (for DPI that drops the upstream regardless of HTTP version). See "Per-uplink fallback transports" in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md).
- client-side session resumption across carriers: WebSocket upgrades carry `X-Outline-Resume-Capable: 1`; the `X-Outline-Session` ID the server returns is cached per uplink (and per (uplink, target) inside the VLESS UDP mux) and sent as `X-Outline-Resume: <hex>` on the next dial, so an outline-ss-rust server with resumption enabled re-attaches the parked upstream and skips the connect to the target. Covers TCP over WS, SS-UDP over WS and VLESS over XHTTP (h1 / h2 / h3, packet-up and stream-one; the token comes back on the response that carries the first downlink chunk). A server without resumption ignores the header; the wire is otherwise unchanged.

### Encryption

- `chacha20-ietf-poly1305`
- `aes-128-gcm`
- `aes-256-gcm`
- `2022-blake3-aes-128-gcm`
- `2022-blake3-aes-256-gcm`
- `2022-blake3-chacha20-poly1305`

### Uplink management

- several uplinks per group
- selection mode:
  - `active_active`: new flows can use different uplinks based on score, stickiness and failover
  - `active_passive`: keep the selected uplink until it becomes unhealthy or enters cooldown. When a manual control-plane switch or a probe-driven failover moves the active uplink away from an in-flight SOCKS5 session, that TCP session is closed with RST (`SO_LINGER {l_onoff=1, l_linger=0}`) so the client reconnects through the new active uplink instead of leaving through the now-passive one (different source IP / ASN). The UDP downlink loop wakes on the same `subscribe_active_uplinks` watch. Counter: `outline_ws_socks_tcp_strict_aborts_total`. `active_active` is not affected.
- routing scope:
  - `per_flow`: decisions are made independently per routing key / target
  - `per_uplink`: one active uplink per transport (`tcp` and `udp`) for the whole process. In `active_passive` the pinned TCP and UDP uplinks do not expire with `sticky_ttl`; established SOCKS TCP tunnels stay on the uplink that completed setup, while non-migratable flows that depend on the old active uplink may be reselected or closed after a switch. Penalty history is not folded into the strict per-transport score.
  - `per_client`: each ingress client sticks to one balancer-chosen uplink, keyed by its source IP (SOCKS5 peer IP, or the LAN device IP behind a TUN router), for `sticky_ttl`, refreshed while active. Different clients spread across uplinks; one client keeps one egress IP, with failover when its pinned uplink goes unhealthy. `active_active` only — under `active_passive` it behaves like `per_flow`. Clients without a determinable source IP share one key.
  - `global`: one active uplink for all new traffic of the process, TCP and UDP. Ranking uses the TCP score, but a UDP-capable active uplink also counts as failed when its UDP probe marks it unhealthy or its UDP runtime cooldown is active. The active global uplink does not expire with `sticky_ttl`, penalty history is not folded into the strict global score, and TUN flows still pinned to the old uplink after a global switch are closed so they reconnect through the new one.
- per-uplink static `weight`
- RTT EWMA scoring
- failure penalties with exponential decay
- sticky routing with TTL
- hysteresis against switching on small score differences
- runtime failover
- `auto_failback = false` by default: the active uplink changes only on failure, never back to a recovered primary on its own
- warm-standby WebSocket pools for TCP and UDP
- active-uplink selection persisted across restarts (TOML state file, debounced async writes)
- scheduled weighted re-selection of the strict active uplink (`active_passive` only): wall-clock `reselect_at` slots or a fixed `reselect_interval`; the rotation always excludes the current active and weights candidates by health/penalty like `health_weighted_selection`; `POST /control/reselect` triggers it on demand. See "Scheduled re-selection" in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md).
- deterministic variant of that rotation (`reselect_sync = true`, requires `reselect_at`): the slot order is derived from group name, uplink names, local day and slot index instead of a random draw, so independent nodes with the same group config pick the same uplink — one egress address for clients that reach either node — without exchanging any messages.

### Health probing

- WebSocket connectivity probes (TCP + TLS + WS handshake; no ping/pong — servers rarely answer WebSocket ping control frames)
- HTTP probes over `websocket-stream`
- DNS probes over `websocket-packet`
- TLS handshake-only probes against a configured SNI through the tunnel; they catch upstream filtering that silently drops `ServerHello` for specific SNIs, which the plain HTTP probe cannot see
- probe concurrency limits
- a separate dial limit for probes
- immediate probe wakeup on runtime failure (at most once per 15 s per uplink)
- consecutive-success counter that gates auto-failback

### TUN

- an existing TUN device only (the process does not create it)
- `tun2udp` with flow lifecycle management, IPv4/IPv6 fragment reassembly and local ICMP echo replies
- userspace `tun2tcp` relay with retransmit, zero-window persist/backoff, SACK-aware receive/send, adaptive RTO and bounded buffers

### Operations

- Prometheus metrics
- Grafana dashboards in [`grafana/`](grafana)
- TLS certificate-expiry tracking for uplinks: gauge `outline_ws_uplink_cert_expiry_timestamp_seconds` and field `cert_not_after_unix_ms` per uplink in `GET /control/topology`
- systemd units with sandboxing (see [systemd](#systemd))
- Linux `fwmark` / `SO_MARK`
- IPv6 listeners, upstreams, probes and SOCKS5 targets

## Current limits

- `tun2tcp` is a userspace TCP relay, not a kernel-equivalent TCP stack.
- Non-echo ICMP on TUN is not supported.
- `probe.http` supports `http://` only. For HTTPS use `[outline.probe.tls]`, which runs a TLS handshake (no HTTP exchange) against a configured SNI. `probe.tcp` must target a speak-first TCP service such as SSH or SMTP, not an HTTP/HTTPS port.
- TCP failover to another uplink happens only before useful payload exchange. An established TCP tunnel is not moved between uplinks; the TUN carrier migration described in [Carrier migration](#carrier-migration-surviving-a-dead-carrier) re-dials the same uplink.

## Repository layout

Paths are relative to `bins/outline-ws-rust/`; shared crates live at the workspace root.

- [`config.toml`](config.toml) — example configuration
- [`systemd/outline-ws-rust.service`](systemd/outline-ws-rust.service), [`systemd/outline-ws-rust@.service`](systemd/outline-ws-rust@.service) — systemd units
- [`grafana/outline-ws-rust-dashboard.json`](grafana/outline-ws-rust-dashboard.json) — main operational dashboard
- [`grafana/outline-ws-rust-hang-diagnostics.json`](grafana/outline-ws-rust-hang-diagnostics.json) — hang diagnostics
- [`src/bootstrap/`](src/bootstrap) — startup sequence: listener binding and persistent state store
- [`src/config/`](src/config) — CLI and config schema, loading, validation
- [`src/proxy/`](src/proxy) — SOCKS5 TCP/UDP ingress (dispatcher, TCP failover, UDP relay)
- [`src/http/`](src/http) — metrics endpoint and control plane
- [`../../crates/outline-uplink/`](../../crates/outline-uplink) — uplink selection, probing, failover, standby pools
- [`../../crates/outline-transport/`](../../crates/outline-transport) — WebSocket / HTTP/2 / HTTP/3 / XHTTP / VLESS transports and the cross-transport `ResumeCache`
- [`../../crates/outline-net/`](../../crates/outline-net) — DNS cache and socket helpers (fwmark, keepalive, buffer sizing)
- [`../../crates/outline-tun/`](../../crates/outline-tun) — TUN relay engines (TCP and UDP)
- [`../../crates/shadowsocks-crypto/`](../../crates/shadowsocks-crypto) — Shadowsocks AEAD helpers
- [`../../crates/outline-wire/`](../../crates/outline-wire) — wire codec shared with the server (`CipherKind`, `TargetAddr`, SS2022 headers, VLESS/mux)
- [`../../crates/outline-metrics/`](../../crates/outline-metrics) — Prometheus registration and session/transport snapshots
- [`../../crates/outline-routing/`](../../crates/outline-routing) — CIDR and domain routing table
- [`../../crates/socks5-proto/`](../../crates/socks5-proto) — SOCKS5 protocol primitives
- [`../../PATCHES.md`](../../PATCHES.md) — inventory of vendored crate patches (one for the whole workspace)

## Build

Run every command below from the workspace root (`outline-proxy/`).

### Prerequisites

- Rust toolchain (stable): `rustup update stable`
- For cross-compilation: [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) and Zig; zigbuild uses the Zig C compiler as the linker, so no per-target cross toolchain is needed.

```bash
cargo install cargo-zigbuild
```

Install the Rust targets:

```bash
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```

Aliases from the root `.cargo/config.toml`:

```bash
cargo ws-release-musl-x86_64
cargo ws-release-musl-aarch64
```

### CI releases

Client workflows live in `.github/workflows/ws-*.yml`; tags of the client carry the `ws-` prefix.

- A push to `main` that touches `bins/outline-ws-rust/**`, `crates/**`, `vendor/**`, `Cargo.toml`, `Cargo.lock` or `.cargo/**` runs `Nightly Release (client)`. It moves the rolling tag `ws-nightly` to that commit and republishes the `Client Nightly` prerelease.
- Nightly publishes `release` builds for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` plus `SHA256SUMS.txt`. Archives are named `outline-ws-rust-nightly-<full-commit-sha>-<target>.tar.gz`.
- To cut a stable release, run the manual `Release (client)` workflow with `major_minor`, e.g. `1.7`. CI finds the latest `ws-v1.7.*` tag, increments the patch, updates `Cargo.toml` and `Cargo.lock`, creates a release commit and pushes it to `main`.
- After the release commit lands on `main`, create and push a signed tag locally (`git tag -s ws-vX.Y.Z -m ws-vX.Y.Z`). The tag push runs `Tag Release (client)`, which builds and publishes the GitHub Release with the same two targets.
- Pushing a `ws-v*` tag manually also runs `Tag Release (client)`.

### Feature flags

| Feature | Default | Effect |
|---|---|---|
| `h3` | yes | HTTP/3 carriers (`ws_h3`, `xhttp_h3`): quinn + sockudo-ws/http3 |
| `metrics` | yes | Prometheus `/metrics` endpoint and transport-layer metrics (prometheus + serde_json) |
| `control` | yes | authenticated control-plane listener (`[control]`) |
| `socks5` | yes | SOCKS5 ingress (`src/proxy`); off in the Android build |
| `tun` | yes | TUN engines (`tun2udp` + `tun2tcp`) |
| `jemalloc` | yes | jemalloc allocator; heap metrics report `heap_mode="exact"`, `GET /control/alloc` returns allocator stats |
| `env-filter` | yes | `RUST_LOG` parsing; without it the log level is fixed at `WARN` (saves ~300 KB on MIPS) |
| `multi-thread` | yes | Tokio work-stealing scheduler; without it `current_thread` (saves ~100–200 KB on MIPS) |
| `mimalloc` | no | previous allocator, kept buildable for comparison; mutually exclusive with `jemalloc` |
| `test-tls` | no | e2e tests only: trusts a self-signed root from `OUTLINE_WS_TEST_TLS_CA_DER`. Never enable in production builds |

### Building the binary

Native build for the current machine:

```bash
cargo build --release -p outline-ws-rust
```

Static x86-64 binary (no glibc dependency):

```bash
cargo zigbuild --release -p outline-ws-rust --target x86_64-unknown-linux-musl
# or
cargo ws-release-musl-x86_64
```

Static AArch64 binary:

```bash
cargo zigbuild --release -p outline-ws-rust --target aarch64-unknown-linux-musl
# or
cargo ws-release-musl-aarch64
```

To drop one feature, disable the defaults and list the rest. Example without `metrics`:

```bash
cargo zigbuild --release -p outline-ws-rust --no-default-features \
  --features h3,control,socks5,tun,jemalloc,env-filter,multi-thread \
  --target x86_64-unknown-linux-musl
```

## Quick start

`--config` defaults to `config.toml` in the current directory. From the workspace root, point it at the example:

```bash
cargo run --release -p outline-ws-rust -- --config bins/outline-ws-rust/config.toml
```

One-shot run with CLI overrides:

```bash
cargo run --release -p outline-ws-rust -- \
  --listen [::]:1080 \
  --tcp-ws-url wss://example.com/SECRET/tcp \
  --tcp-mode h3 \
  --udp-ws-url wss://example.com/SECRET/udp \
  --udp-mode h3 \
  --method chacha20-ietf-poly1305 \
  --password 'Secret0'
```

Client settings for this example: SOCKS5 host `::1` or `127.0.0.1`, port `1080`.

`listen = "[::]:1080"` creates a dual-stack listener on most systems. If your platform does not map IPv4 onto IPv6 sockets, bind an additional IPv4 listener.

### `hev-socks5-tunnel` compatibility

`outline-ws-rust` accepts both UDP relay modes of [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel):

```yaml
socks5:
  address: '127.0.0.1'
  port: 1080
  udp: 'udp'      # standard SOCKS5 UDP ASSOCIATE
  # udp: 'tcp'    # hev FWD UDP / UDP-in-TCP (CMD=0x05)
  # pipeline: true
```

- `udp: 'udp'` uses standard SOCKS5 `UDP ASSOCIATE`.
- `udp: 'tcp'` uses the `hev-socks5` TCP-carried UDP relay (`CMD=0x05`).
- `pipeline: true` works, including with username/password auth.

## Configuration

The process reads the file given by `--config` / `PROXY_CONFIG` (default `config.toml`). The example below is an excerpt; the full commented example is [`config.toml`](config.toml).

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

# The multi-instance dashboard has moved to the outline-ui service
# (see bins/outline-ui/README.md). This binary serves only [metrics]
# and [control] below.

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
# Cap on concurrent *tunnelled* flows — the ones that each dial a carrier —
# across BOTH the TCP and UDP paths. A carrier costs ~28x a direct flow's socket
# in RSS (measured 0.279 MiB vs 0.010 MiB against a plain ws:// upstream, more
# with TLS/H3), so on a memory-capped host `max_flows` is reached long after the
# memory is gone: a 2026-08-08 flow burst held ~1155 flows against the 4096
# limit while its 419 carriers drove RSS from 199 to 757 MiB and the cgroup's
# MemoryHigh throttle froze the runtime. Overflow evicts the least-recently-seen
# tunnelled flow of the same protocol, exactly as max_flows does; direct flows
# are never charged against it. Size it from
# `outline_ws_tun_carrier_flow_memory_estimate_bytes` and the RAM you are
# willing to spend, and watch `outline_ws_tun_carrier_flows_active` to see
# whether it binds. Must not exceed max_flows. Default 0 (off).
#
# NOTE: this used to bind on the UDP path alone, so a value tuned before that
# change is effectively twice as strict now — the two paths together used to
# reach roughly 2x it (256 UDP alongside 318 TCP was measured in production).
# Revisit the number when upgrading.
# max_carrier_flows = 0
# idle_timeout_secs = 300
# Process-wide cap on concurrent upstream dials, shared by the TCP and UDP
# engines. A flow burst dials one carrier handshake (TLS/WS/QUIC) per flow;
# over the cap, connect tasks queue for a permit (held for the dial only, never
# the flow's lifetime) and the burst handshakes in fast waves instead of all at
# once. Steady-state flow concurrency is unaffected. 0 disables the gate.
# max_concurrent_upstream_dials = 32
# Built-in IKE / IPsec NAT-T bypass — see "TUN mode" below.
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
# Domains included for sniff override (TCP + QUIC): when non-empty, ONLY hosts
# matching at least one suffix are rewritten to a domain target; all other hosts
# keep the literal IP. Default empty (override all, except sniff_override_exclude).
# sniff_override_include = ["youtube.com", "instagram.com"]
# sniff_override_include_file = "lists/override-include.lst"
# Domains excluded from sniff override (TCP + QUIC): a sniffed host matching any
# suffix keeps the literal IP instead of a domain. For sites where the client's
# own DNS beats the exit re-resolving (geo-wrong CDN edge). Default empty.
# sniff_override_exclude = ["strava.com"]
# sniff_override_exclude_file = "lists/override-exclude.lst"
# file_poll_secs = 60 # Polling interval in seconds to auto-reload domain files on mtime change

# [tun.tcp]
# connect_timeout_secs = 10
# handshake_timeout_secs = 15
# half_close_timeout_secs = 60
# max_pending_server_bytes = 2097152
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
# against a server with resumption disabled (the server default). See "TUN mode".
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
rtt_ewma_halflife_secs = 300
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
# disable_udp_gso = true
# ipv6_first = true
# ipv4_only = true
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

### Config behavior

- `transport` accepts `ss` (default; alias `shadowsocks`) or `vless`. `ws` / `websocket` are deprecated aliases for `ss` and will be removed. VLESS uses the same carrier fields as `ss` (`ipv6_first`, `fwmark`, …) but takes its own URL/mode pair — `vless_ws_url` or `vless_xhttp_url` plus `vless_mode` — and authenticates with one `vless_id` instead of Shadowsocks `method` + `password`; `tcp_ws_url` / `udp_ws_url` with `transport = "vless"` are rejected at parse time. VLESS UDP opens one session per destination inside the uplink, bounded by `vless_udp_max_sessions` (default `256`, LRU eviction), with idle eviction after `vless_udp_session_idle_secs` (default `60`, `0` disables) checked every `vless_udp_janitor_interval_secs` (default `15`). These three keys live in `[outline.load_balancing]` or on each `[[uplink_group]]`.
- `link = "vless://UUID@HOST:PORT?type=...&security=...&alpn=...#NAME"` configures a VLESS uplink from one share-link URI instead of `vless_id` / `vless_*_url` / `vless_mode`; `transport = "vless"` is implied. An `ss://` link (SIP002 userinfo) configures an SS uplink the same way. The value is also accepted by `--vless-link` (alias `--link`, env `OUTLINE_VLESS_LINK`) and by the `/control/uplinks` payload (`link`, alias `share_link`). Mixing `link` with the explicit fields is rejected. Query parameters and constraints: [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md#5-vless-share-link-uris).
- At least one ingress is required: `--listen` / `[socks5].listen` and/or `[tun]`. Without either, the process exits with an error instead of binding `127.0.0.1:1080`.
- `tcp_mode` / `udp_mode` (`transport = "ss"`) and `vless_mode` (`transport = "vless"`) select the carrier: `ws_h1` / `ws_h2` / `ws_h3` (WebSocket Upgrade) or `xhttp_h1` / `xhttp_h2` / `xhttp_h3` (XHTTP; SS takes the URL from `tcp_xhttp_url` / `udp_xhttp_url`, VLESS from `vless_xhttp_url`). The old values `http1` / `h1`, `h2`, `h3` are accepted as aliases of `ws_h1`, `ws_h2`, `ws_h3`; `quic` is rejected (raw QUIC uplinks were removed). Per-shape config blocks, fallback chains and resume behaviour: [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md).
- `ipv6_first` (default `false`) makes the uplink prefer IPv6 addresses over IPv4 for TCP, UDP, H1, H2 and H3 connections.
- `ipv4_only` (default `false`) drops AAAA records when resolving the uplink's servers. Set it on hosts without IPv6 connectivity, where IPv6 attempts fail with `NetworkUnreachable (OS 101)` and make the uplink flap. With `ipv4_only = true`, `ipv6_first` is ignored. Inherited from `[outline]` by `[[outline.uplinks]]` and `[[outline.uplinks.fallbacks]]` unless overridden.
- `disable_udp_gso` (default `false`, `[[outline.uplinks]]` and `[[outline.uplinks.fallbacks]]`) keeps the uplink's QUIC sockets (`ws_h3` / `xhttp_h3`) off UDP GSO, so quinn sends one datagram per `sendmsg`. Set it on an uplink whose egress rejects segmented sends — typically one that `fwmark` routes onto a VLAN of a NIC without TX checksum offload: there every GSO send fails with `EIO` and each new QUIC connection loses its first handshake flight (~1 s extra per dial). TCP carriers are not affected. Inherited by fallbacks unless overridden. See "Egress without UDP GSO" in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md).
- `method` also accepts `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` and `2022-blake3-chacha20-poly1305`; for these, `password` must be a base64-encoded PSK of exactly the cipher's key length.
- `[[socks5.users]]` enables local SOCKS5 username/password auth for several users; each entry needs both `username` and `password`. `[socks5] username` + `password`, or `--socks5-username` / `--socks5-password`, configure a single user.
- The same SOCKS5 listener accepts standard `UDP ASSOCIATE` and `hev-socks5` `UDP-in-TCP` (`CMD=0x05`); no extra switch is needed.
- `[outline.probe] min_failures` (default `3`): consecutive probe failures before an uplink is declared unhealthy. The same value is the consecutive-success threshold for `auto_failback`. Lower it to `1` to fail over on the first failed probe.
- `[outline.probe] interval_secs` (default `120`): probe cycle period. Values below 60 s log a warning at startup: frequent probe handshakes can trip upstream rate limits.
- `tcp_chunk0_failover_timeout_secs` (default `10`, `[outline.load_balancing]` or per `[[uplink_group]]`): how long to wait for the first upstream response bytes after the last client request activity before TCP chunk-0 failover to another uplink is allowed. Raise it if uplinks switch on slow first-byte responses.
- `auto_failback` (default `false`, `[outline.load_balancing]` or per `[[uplink_group]]`): whether traffic returns to a recovered higher-priority uplink.
  - `false`: the active uplink is replaced only when it fails. Once on a backup, the proxy stays there until the backup fails. Use this to avoid the connection resets a proactive return causes.
  - `true`: while the current active is healthy and a candidate with a higher `weight` (or equal weight and lower config index) exists, traffic returns to that candidate after it has passed `min_failures` consecutive probe cycles. Priority is `weight`, not EWMA RTT: under load the active uplink's EWMA rises while an idle backup looks faster, and comparing EWMA would switch on that. Failback only moves toward higher weight (`1.0 → 1.5 → 2.0`); moving to a lower-weight uplink requires a probe-confirmed failover.
- `mode_downgrade_secs` (per group, default `60`, alias `h3_downgrade_secs`): how long an uplink that failed on its advanced carrier (e.g. an H3 application error such as `H3_INTERNAL_ERROR`) stays capped one rank lower (`ws_h3 → ws_h2`, `xhttp_h3 → xhttp_h2`) before the configured carrier is retried. Applies to `ss` and `vless`. `0` disables the downgrade.
- `carrier_degraded_failover_secs` (per group, default `3 × mode_downgrade_secs`): carrier-quality failover for strict (`active_passive`) selection. An uplink whose probes pass on its TCP fallback counts as healthy, so without this knob it would keep the active slot while every dial is capped below the configured carrier (`ws_h3 → ws_h2`, TCP over TCP). When the active uplink has run below its configured carrier under one unbroken downgrade window for at least this many seconds, and the group has a probe-healthy candidate of equal or higher `weight` whose carrier is not degraded and whose probe-success streak has reached `min_failures`, selection soft-switches to that candidate. A single flap cannot trigger it: one window expires after `mode_downgrade_secs`, so only failures that keep extending the window cross the threshold. `0` disables. Works with either `auto_failback` value; a lower-weight candidate never takes the slot on carrier quality alone.
- `state_path` (optional): TOML file where the active-uplink selection is persisted across restarts. Default: the config path with the extension replaced by `.state.toml` (`config.toml` → `config.state.toml`). If the file cannot be written (e.g. the config lives in `/etc/` under `ProtectSystem=strict`), the process logs a warning at startup and runs without persistence. The bundled units set `STATE_PATH=/var/lib/outline-ws-rust/_default/state.toml` (template: `/var/lib/outline-ws-rust/<instance>/state.toml`). Only the active uplink name is stored; EWMA and penalties are rebuilt within one probe cycle after restart.
- Each `[[uplink_group]]` has its own probe loop, standby pool, sticky-routes store, active-uplink state and load-balancing policy; groups do not share runtime state.
- `[outline.probe]` is a template: each group inherits it, and `[uplink_group.probe]` overrides individual fields. Probe sub-tables (`ws` / `http` / `dns` / `tcp` / `tls`) are replaced as a whole: if a group sets `[uplink_group.probe.http]`, the template's `[outline.probe.http]` is dropped for that group. Application-level probes (`http` / `tcp` / `tls`) are mutually exclusive: one runs per cycle, priority `tls → http → tcp`.
- Uplink names must be unique across all groups: Prometheus labels use `uplink="..."` without a group qualifier.
- The `[bypass]` section was removed. Move bypass prefixes to a `[[route]]` with `via = "direct"`; a config that still has `[bypass]` fails to load with a migration error.
- Uplinks, the probe template and load-balancing settings live under `[outline]` (`[[outline.uplinks]]`, `[outline.probe]`, `[outline.load_balancing]`). The old flat layout (top-level `tcp_ws_url` / `[probe]` / `[[uplinks]]` / `[load_balancing]`) still loads and logs a deprecation warning. Without any uplink entry, top-level `tcp_ws_url` / `password` or the CLI flags (`--tcp-ws-url`, `--password`, …) create a single-uplink group named `default`.
- CLI flags and environment variables override file settings. `--metrics-listen` enables metrics without `[metrics]`; `--tun-path` enables TUN without `[tun]`; `--control-listen` + `--control-token` enable the control plane without `[control]` — both must be given, either alone is a startup error.
- `direct_fwmark` (optional, top level): `SO_MARK` for TCP and UDP sockets of `direct`-routed connections. Set it when bypass traffic must be marked for policy routing, e.g. so that the bypass route is not captured by the TUN interface again.
- `[dial] timeout_secs` (default `10`, clamped to `2..=120`): upper bound on one fresh carrier dial — TCP + TLS + HTTP upgrade for WS/XHTTP, or the QUIC + HTTP/3 handshake — and, at 70 % of it, on opening a stream on an established H3 connection. 10 s fits broadband and LTE. On 2G a round trip is close to a second and the certificate chain alone takes seconds, so a 10 s budget expires mid-handshake, every attempt counts as a runtime failure, and retries use up the bandwidth the handshake needed: the uplink stays "up" and carries nothing. Raise the value for such links. Cost: worst-case failover latency, because this bound is what stops a dial into a black hole from holding the `h3 → h2 → h1` chain for the OS SYN-retransmit budget (Linux ~127 s).
- `[tcp_timeouts]` bounds SOCKS5 TCP sessions; values are in seconds:

  | Key | Default | Effect |
  |---|---|---|
  | `socks_upstream_idle_secs` | `300` | close a tunnelled SOCKS5 session when no payload moved in either direction for this long; keepalive frames do not reset the timer. Reclaims FDs of connections that TUN interceptors open and drop without FIN |
  | `direct_idle_secs` | `120` | the same for `direct` sessions |
  | `post_client_eof_downstream_secs` | `600` | after the client half-closes, how long the downstream may take to finish and send FIN. Long-running requests (large upload, then minutes of server think time) need this; 30 s cut them off mid-response |
  | `upstream_response_secs` | `15` | chunk-0 response deadline per uplink when no failover candidate is left |

### CLI flags and environment variables

| Flag | Env | Sets |
|---|---|---|
| `--config` | `PROXY_CONFIG` | config file path (default `config.toml`) |
| `--listen` | `SOCKS5_LISTEN` | SOCKS5 listen address |
| `--socks5-username` | `SOCKS5_USERNAME` | single SOCKS5 user |
| `--socks5-password` | `SOCKS5_PASSWORD` | single SOCKS5 user's password |
| `--transport` | `OUTLINE_TRANSPORT` | `ss` or `vless` |
| `--tcp-ws-url` | `OUTLINE_TCP_WS_URL` | SS TCP WebSocket URL |
| `--tcp-xhttp-url` | `OUTLINE_TCP_XHTTP_URL` | SS TCP XHTTP base URL |
| `--tcp-mode` | `OUTLINE_TCP_MODE` | SS TCP carrier |
| `--udp-ws-url` | `OUTLINE_UDP_WS_URL` | SS UDP WebSocket URL |
| `--udp-xhttp-url` | `OUTLINE_UDP_XHTTP_URL` | SS UDP XHTTP base URL |
| `--udp-mode` | `OUTLINE_UDP_MODE` | SS UDP carrier |
| `--vless-ws-url` | `OUTLINE_VLESS_WS_URL` | VLESS WebSocket URL |
| `--vless-xhttp-url` | `OUTLINE_VLESS_XHTTP_URL` | VLESS XHTTP base URL |
| `--vless-mode` | `OUTLINE_VLESS_MODE` | VLESS carrier |
| `--vless-link` (`--link`) | `OUTLINE_VLESS_LINK` | uplink from a `vless://` or `ss://` share link |
| `--method` | `SHADOWSOCKS_METHOD` | Shadowsocks cipher |
| `--password` | `SHADOWSOCKS_PASSWORD` | Shadowsocks password / PSK |
| `--fwmark` | `OUTLINE_FWMARK` | uplink `SO_MARK` |
| `--ipv6-first` | `OUTLINE_IPV6_FIRST` | prefer IPv6 for the uplink |
| `--ipv4-only` | `OUTLINE_IPV4_ONLY` | IPv4 only for the uplink |
| `--metrics-listen` | `METRICS_LISTEN` | metrics listen address |
| `--control-listen` | `CONTROL_LISTEN` | control-plane listen address |
| `--control-token` | `CONTROL_TOKEN` | control-plane bearer token |
| `--tun-path` | `TUN_PATH` | TUN device path |
| `--tun-name` | `TUN_NAME` | TUN interface name |
| `--tun-mtu` | `TUN_MTU` | TUN MTU |
| `--worker-threads` | `WORKER_THREADS` | Tokio worker threads (default: CPU count) |
| `--thread-stack-size-kb` | `THREAD_STACK_SIZE_KB` | stack per Tokio thread in KiB (default `2048`) |
| `--state-path` | `STATE_PATH` | active-uplink state file |
| `--fingerprint-profile` | `OUTLINE_FINGERPRINT_PROFILE` | browser fingerprint strategy: `off`, `stable`, `per_host_stable`, `random` |

## Policy routing

Routing by destination, evaluated first-match-wins, with one explicit `default = true` rule. Each rule picks a target with `via = "..."`:

- a group name (one of the declared `[[uplink_group]]`s): the connection goes through that group's uplink manager;
- `direct`: forwarded outside any uplink (what `[bypass]` used to do);
- `drop`: SOCKS5 `REP=0x02 (connection not allowed)` for TCP, silent drop for UDP.

IP targets are matched against each rule's CIDR prefixes. Domain-name targets (a SOCKS5 client handing over a hostname for remote resolution) never match a CIDR prefix; they are matched against each rule's `domains` suffixes and fall through to the default when no rule lists them. The proxy does not resolve a domain locally to route it: that would send the DNS query outside the tunnel and break remote resolution.

Rules can be edited at runtime through `/control/routes` and reordered through `/control/routes/reorder`; see [Control plane](#control-plane) for the endpoints and the hot-apply limitation.

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

| Field | Default | Meaning |
|---|---|---|
| `prefixes` / `file` / `files` | — | inline CIDR list and/or files with one CIDR per line (`#` comments and blank lines ignored). All sources are merged into the rule's CIDR set; `file` is shorthand for a one-entry `files`, both may be combined |
| `domains` / `domain_file` / `domain_files` | — | domain suffixes matched against domain targets (same file format, one suffix per line). `example.com` matches the domain and any subdomain (`a.b.example.com`) on label boundaries; matching is case-insensitive, a trailing dot is ignored, `.example.com` and `*.example.com` mean the same suffix. `"*"` matches every domain — use it as a catch-all so domain targets get an explicit route. A rule may combine CIDR and domain sources: IPs match the CIDR side, domains the domain side |
| `file_poll_secs` | `60` | how often each file in `file` / `files` / `domain_file` / `domain_files` is `stat`-ed; contents are reloaded on mtime change |
| `via` | — | target for matching traffic; required except on the `default = true` rule, where it is the fallthrough target |
| `fallback_via` / `fallback_direct` / `fallback_drop` | — | mutually exclusive; used when `via` is a group with zero healthy uplinks at dispatch time |
| `invert` | `false` | the rule matches addresses not in its prefix set. CIDR side only; cannot be combined with `domains` (rejected at load — use a separate domain rule) |
| `default` | — | exactly one rule must set `default = true`; it matches everything the previous rules did not and must not set prefix or domain sources |

### Prefix matching

Each rule's inline and file prefixes are merged into a [`CidrSet`](../../crates/outline-routing/src/cidr.rs): sorted `[start, end]` ranges (IPv4 as `u32`, IPv6 as `u128`) with overlapping and adjacent ranges merged. Lookup is a binary search (`partition_point`), O(log n) per rule.

### Hot-reload

Every rule with at least one `file` / `files` / `domain_file` / `domain_files` entry gets a background task that checks the mtime of each listed path every `file_poll_secs`. When one changes, the rule's CIDR and domain sets are rebuilt from the inline entries plus all files and swapped atomically (`ArcSwap`); other rules are not touched. A read or parse error keeps the previous sets and logs a warning.

### Direct session idle timeout

`direct` connections are closed after 120 s (`[tcp_timeouts] direct_idle_secs`) without bytes in either direction, and their FDs are reclaimed. Clients that open TCP connections (DNS-over-HTTPS, DNS-over-TLS) and abandon them without FIN would otherwise keep both sockets open. Any data in either direction resets the timer.

### Fallback semantics

When `via` resolves to a group with no healthy uplink, the rule's fallback target is used instead (one level, no recursion). Health is read at dispatch time via `UplinkManager::has_any_healthy(transport)`, without building a candidate list or touching sticky routes. When the primary group recovers, new connections go through it again; the fallback is consulted only at dispatch.

### Group-level bypass (`bypass_when_down`)

Instead of `fallback_direct = true` on every route, a group can set `bypass_when_down = true` on its `[[uplink_group]]`: traffic routed to the group goes `direct` while the group has no healthy uplink, including the implicit "everything to the default group" dispatch when no `[[route]]` is configured. An explicit route fallback takes precedence; the bypass then applies (one level deep) to the group the fallback lands on. The decision is re-evaluated per dial / datagram / flow, so traffic returns to the tunnel as soon as any uplink recovers. On hosts where TUN holds the default route, set `direct_fwmark` so bypassed sockets do not loop back into TUN. See "Bypass on a fully-down group" in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md).

## Transport modes

The four uplink shapes — Shadowsocks over WebSocket, Shadowsocks over XHTTP, VLESS over WebSocket and VLESS over XHTTP — are documented with TOML examples and dial-time fallback chains in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md). This section covers runtime details not in that reference.

Choosing a carrier:

- `ws_h1` works through any reverse proxy that passes WebSocket Upgrade;
- `ws_h2` needs a reverse proxy and origin that support RFC 8441;
- `ws_h3` needs QUIC (UDP) reachability to the server;
- `xhttp_h2` / `xhttp_h3` when WebSocket Upgrade is blocked on the path; the dial falls through to `xhttp_h1` when QUIC and the h2 ALPN are blocked too (h1 has lower throughput but uses the same URL as xray).

QUIC endpoints. Every H3 connection (`ws_h3`, `xhttp_h3`) gets its own QUIC endpoint and UDP socket on a fresh local port, alive for exactly as long as the connection. A NAT translation stuck on a dead destination therefore affects one connection, not every later dial. Each endpoint allocates a ~2.9 MiB receive buffer on Linux with GRO; the gauge `outline_ws_h3_endpoints_active{kind}` counts live endpoints. `fwmark` is applied to the socket before the first `sendmsg`.

A handshake still unanswered after 1 s starts a second dial from a fresh local port, and a third at 3 s; the first to finish is used. Some paths discard a whole UDP flow, so retransmitting from the same port cannot get through, while a new port is a new flow. A healthy handshake finishes in about two round trips and never starts a second dial. `outline_ws_quic_dial_hedges_total{kind,result}` counts dials that raced: `result="won"` when a later attempt finished first, `result="lost"` when the first one won anyway.

QUIC keep-alive PINGs go out every 8–12 s (per-process jitter; `[quic] keepalive_secs` overrides it), so NAT mappings do not expire and the server can detect dead connections before the idle timeout (`[quic] idle_timeout_secs`, default 30 s from the browser profile).

Mode downgrade window. After a failure on an advanced carrier (H3 / `xhttp_h3`), the uplink stays one rank lower for `mode_downgrade_secs` (default 60 s; alias `h3_downgrade_secs`; `0` disables). TCP probe failures on H3 uplinks open the same window; otherwise, in `active_passive + global`, a probe that alternates between pass and fail would trigger a failover every cycle. The two layers (per-host cache + per-uplink window) are described in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md#downgrade-window-mechanics).

Scoring during a downgrade window (`per_flow` scope): while the window is open, `failure_penalty_max_ms` is added to the uplink's effective latency on top of the normal failure penalty. As the normal penalty decays, this term keeps `active_active + per_flow` flows from moving back to the primary while it runs on the H2 fallback, until the window closes.

Warm-standby slots follow the downgrade: while an uplink is capped from H3 to H2, new standby connections are opened with H2.

Transport handshake timeouts. Every connect path has an upper bound, so a black-holed server cannot stall new sessions for minutes while the uplink still counts as healthy:

| Situation | Bound (defaults) | Without the bound |
|---|---|---|
| Fresh connect (TCP/QUIC + TLS + HTTP handshake), H1 / H2 / H3 | `[dial] timeout_secs`, 10 s | Linux TCP SYN retransmits ~127 s (H1/H2); QUIC idle timeout (H3) |
| New stream on a shared H2 connection | `[dial] timeout_secs`, 10 s | waits for the dead connection |
| New session on a pooled H3 connection | 8 × the connection's smoothed RTT, at least 3 s, at most 70 % of `[dial] timeout_secs` (7 s); then the session redials on a fresh connection | waits until the QUIC idle timeout closes the connection |

A pooled connection whose path died (NAT rebinding, late server close, silent loss) still looks open to the client library; these bounds catch that. A timeout counts as an upstream runtime failure: the pooled entry is invalidated on the next open, `report_runtime_failure` sets a cooldown and wakes the probe. In `active_passive + global` the active uplink is replaced only after the probe confirms the failure on a fresh connect of its own, so a transient pool glitch does not change the exit IP, and recovery from a really unreachable primary takes about one probe cycle.

Shared connection reconnect. When a shared H2 or H3 connection drops and N sessions try to reconnect at once, one new handshake is performed. A per-server-key `tokio::sync::Mutex<()>` serialises the slow path: the first waiter connects and caches the connection; the others find it under the lock and reuse it instead of opening N TLS handshakes to the same server.

SOCKS5 negotiation aborts. When a local SOCKS5 client (a TUN interceptor such as sing-box or Clash) closes the connection after the greeting but before or during the CONNECT request, the resulting `early eof` / `failed to read request header` errors are logged at `debug`, not `warn`. TUN interceptors do this when they flush their connection pool during reconnects.

## UDP over HTTP/3 datagrams

On `ws_h3` and `xhttp_h3`, client UDP (Shadowsocks / SS2022 and VLESS) can ride HTTP/3 DATAGRAM frames (RFC 9297) bound to the carrier's request stream instead of the stream itself. This removes head-of-line blocking and the double retransmission of QUIC inside QUIC. Per-protocol rules: [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md#udp-over-http3-datagrams).

```toml
[quic]
# Offer UDP over HTTP/3 datagrams (default true). false: never offer them,
# UDP stays on the stream exactly as before. Read once at startup: takes effect after a restart.
# udp_datagrams = true
```

- Agreement. The client sends `x-outline-udp-datagram: 1`; the server echoes it to agree (server key `[server.h3] udp_datagrams`, default `true`). Without the echo UDP stays on the stream, byte for byte as before, so either side may run an older version.
- Scope. Only `ws_h3` / `xhttp_h3`, only UDP plans, never with the Safari fingerprint profile (it advertises no `max_datagram_frame_size`).
- Sizes. The choice is made per packet against the current `max_datagram_size()`; a packet that does not fit goes over the stream. The client starts at an MTU of 1200 before PMTUD, so right after connect most full-size packets still use the stream. The server's maximum UDP payload is 1452. Datagram buffers are 1 MiB on both sides.
- Rollout. Servers first, then clients; either order works. Rollback: set `udp_datagrams = false` on the misbehaving side and restart that service (no rebuild).

Path MTU cache. The client stores the path MTU each H3 path settled at (keyed by server, port, fwmark and a hash of the local source address, i.e. the network it is on) in a file next to the state file with the extension `.pmtu` (default `<config>.state.pmtu`; with the bundled unit `/var/lib/outline-ws-rust/_default/state.pmtu`). The next dial on the same path probes that size first: one MTU probe instead of the 1326 → 1389 → 1420 → … ladder a passive observer would see on every connection.

| Cached value | Lifetime | Effect on the next connection |
|---|---|---|
| 1452 (H3 upper bound) | 3 days after the path first settled at it | first probe and, once confirmed, the connection's ceiling |
| below 1452 | 1 hour | the same; the short lifetime keeps a search that settled low after a spurious probe loss from capping connections for days |
| expired, up to 30 days old | — | first probe that only seeds the search: the search continues above it and the result is stored again |

A stale value (the path shrank) costs one rejected probe size, then the regular search runs below it. If a search rejected a size, the connection is capped one below the smallest rejected size, so an unchanged path pays its rejected size once per connection, not on every 10-minute re-search. The Initial stays 1200 bytes.

Metrics (on `/metrics`):

| Metric | Labels | Meaning |
| --- | --- | --- |
| `outline_ws_udp_h3_datagrams_total` | `direction`, `transport`, `proto` | UDP packets carried as H3 datagrams (`up` = handed to quinn, which may drop the oldest when its send buffer is full) |
| `outline_ws_udp_h3_datagram_fallback_total` | `direction`, `transport`, `proto`, `reason` | packets / VLESS records of a negotiated session that rode the stream; `reason` for `up`: `unarmed` (VLESS, sent before the server's first reply), `too_large` (did not fit the datagram size), `send_failed` (quinn refused it otherwise); for `down` always `stream` (the server's own counter says why) |
| `outline_ws_udp_h3_datagram_dropped_total` | `reason` | inbound datagrams dropped: `unknown_stream`, `closed_stream` (the stream closed less than 10 s ago), `malformed`, `queue_full` (a burst overflowed the stream's bounded receive queue), `queue_stalled` (it overflowed while its consumer had not read for 50 ms), `early` (VLESS, before the response header) |
| `outline_ws_udp_h3_datagram_sessions_total` | `transport`, `state` | offers by outcome, `negotiated` / `declined`; counts anchor streams, including standby-pool refills and probe dials |
| `outline_ws_quic_path_mtu_bytes` | `transport` | histogram of the path MTU of datagram connections, sampled every 10 s, not at close (a connection shorter than 10 s adds no point; black holes and lost probes are still flushed on close); 1200 is the QUIC minimum after a black hole, where packets of roughly 1100+ bytes ride the stream |
| `outline_ws_quic_black_holes_total` | `transport` | 10 s samples in which a datagram connection detected an MTU black hole (each detection drops the path MTU to 1200), at most one per sample: a dying connection re-fires the detector thousands of times a minute |
| `outline_ws_quic_mtu_probes_lost_total` | `transport` | lost DPLPMTUD probes on datagram connections |

## Carrier padding

Optional application-layer padding for WebSocket and XHTTP dials — the client half of the server's padding feature. Each Shadowsocks chunk or VLESS frame is wrapped in a length-delimited `real_len | pad_len | real | pad` frame, so the outer TLS record size no longer follows the payload size. TLS-in-TLS classifiers use that record-size correlation.

- Global default plus per-uplink override. `[padding]` holds the scheme parameters and the default on/off (`enabled`, default `false`); each `[[outline.uplinks]]` may set `padding = true` / `padding = false`. A dial uses the per-uplink value when set, else the global default (the same override shape as the per-uplink `fingerprint_profile`). Either keep the default off and set `padding = true` on uplinks that point at your padded server endpoints, or keep it on and set `padding = false` on a VLESS uplink aimed at a third-party server (xray / sing-box). A padded dial (SS and VLESS, TCP and UDP) must point at server endpoints that are padded too.
- Set by config on both sides, not negotiated. On outline-ss-rust the matching `[[endpoint]]` must have `padded = true`; otherwise padded frames reach a plain decoder and the session fails.
- Cover traffic. With `cover = true` an idle connection emits pad-only frames at a jittered interval (`cover_jitter_min_ms` … `cover_jitter_max_ms`, defaults 250 / 1500).

Covers SS and VLESS over WebSocket (h1/h2/h3) and over XHTTP. UDP is padded per datagram on every WS carrier — SS-UDP (split: list its path; combined: the shared base path) and VLESS-UDP. Full reference: [`docs/PADDING.md`](../../docs/PADDING.md); the `[padding]` block in `config.toml` lists the keys.

## Uplink selection and runtime behavior

Each uplink has its own:

- TCP URL and mode
- UDP URL and mode
- cipher and password (or `vless_id`)
- optional Linux `fwmark`
- priority via `weight`. Among healthy candidates the highest weight always wins, regardless of EWMA; use it to mark backups that failover and sticky routing must not drift onto. Equal weights are ordered by the EWMA-based score, then by config index.

Selection pipeline:

1. Health probes update the latest raw RTT and EWMA RTT.
2. Probe-confirmed failures add a decaying failure penalty. With probes enabled, a runtime failure (e.g. an H3 connection reset under load) only sets a temporary cooldown; the penalty is added when a probe confirms the failure (`consecutive_failures ≥ min_failures`). Transient errors under load therefore do not accumulate penalties on a healthy uplink.
3. Effective latency = EWMA RTT + current penalty.
4. Candidates are sorted: healthy first, then `weight` (higher first), then `effective_latency / weight`, then config index. The score only ranks uplinks of the same weight.
5. Sticky routing and hysteresis keep flows on their uplink unless the score difference exceeds `hysteresis_ms`.
6. Warm-standby pools hold pre-dialed connections, so a new session skips the handshake.

Sticky-route cap: the sticky-route table holds at most 100 000 per-flow entries. With large NAT pools or many clients in `per_flow` scope, new per-flow entries beyond the cap are not stored and the flow gets a fresh latency-ordered selection. Global and per-transport pins (`global` and `per_uplink` scopes) are always stored.

Routing scope:

- `per_flow`: different targets can use different uplinks.
- `per_uplink`: one selected uplink per transport, so TCP and UDP may use different uplinks. In `active_passive` each transport keeps its pinned uplink until failover or explicit reselection; penalties do not affect the strict per-transport score.
- `global`: one selected uplink for all new traffic until failover or explicit reselection. TCP score ranks, but a UDP-capable active uplink must also keep UDP healthy: a UDP probe failure or UDP runtime cooldown triggers a global failover. Penalties do not affect the strict global score.

Auto-failback (`auto_failback`, default `false`):

- `false`: the active uplink is replaced only when it fails (enters cooldown or turns unhealthy). While it is healthy it stays active even if a higher-priority uplink has recovered. This avoids the connection resets a proactive return to the primary causes.
- `true`: while the current active is healthy and a probe-healthy candidate with a higher `weight` (or equal weight and lower config index) exists, traffic returns to that candidate after it has passed `min_failures` consecutive probe cycles. Priority is `weight`, not EWMA, because the active uplink's EWMA rises under load. Failback only moves toward higher weight; moving to a lower-weight uplink requires a probe-confirmed failover.

Scheduled re-selection: `reselect_at` (wall-clock `"HH:MM"` slots, due for up to 90 s after the configured time) or `reselect_interval` (a fixed period) forces a weighted-random rotation of the strict active uplink in `active_passive` mode. The current active is always excluded; the winner is drawn among healthy, enabled, non-cooldown candidates weighted by `penalty_weight × weight` (floored by `health_weight_floor`). The two keys are mutually exclusive; both require `active_passive`. `POST /control/reselect` runs the same rotation on demand. See "Scheduled re-selection" in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md).

**Warning:** with `auto_failback = true` the draw can land on a lower-weight uplink, and the next run of consecutive healthy probes on the higher-weight uplink reverts the move through failback. Give the group equal `weight` if the scheduled move must stick, or keep `auto_failback = false` (the default).

Synchronized re-selection: `reselect_sync = true` (requires `reselect_at`) replaces the random draw with a deterministic one. The slot's preference order is derived from the group name, the uplink names, the local calendar day and the slot index; the active uplink becomes the first entry of that order that is healthy on this node. Independent nodes with the same group config therefore choose the same uplink without exchanging anything, and clients that reach either node keep one egress address. Health, cooldown and admin state stay local: a node whose uplink dies fails over immediately, and if only one node sees the failure the pair stays split until the next slot. At startup the slot decision overrides an active uplink restored from the state file, and `POST /control/reselect` is idempotent within a slot. All nodes of one sync domain must use the same timezone. See "Synchronized re-selection" in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md).

Penalty-aware failover: when the active uplink enters cooldown, replacement candidates are sorted healthy first → remaining cooldown → `weight` (higher first) → penalty-aware score (`(EWMA + penalty) / weight`) → config index. A deliberately down-ranked backup is not promoted by a faster probe RTT alone; within one weight, the penalty term keeps three or more equal uplinks from oscillating (without it, a primary that just failed and was cleared by a probe would win again on its better raw EWMA).

Runtime failover:

- UDP can switch uplinks within an active association after a send/read failure.
- TCP can fail over before a usable tunnel is established.
- Established TCP tunnels are not moved to another uplink.

## Health probes

Probe types:

| Type | What it checks |
|---|---|
| `ws` | TCP + TLS + WebSocket handshake to the uplink. No ping/pong frames (many servers do not answer them). Confirms a new connection can be opened; data-path integrity is checked by `http` / `dns` |
| `http` | HTTP `HEAD` over `websocket-stream`; status `200..400` is success |
| `dns` | DNS exchange over `websocket-packet`; checks the UDP data path |
| `tcp` | connect to a speak-first TCP service through the tunnel |
| `tls` | TLS handshake against a configured SNI through the tunnel, no HTTP exchange |

Probe settings (`[outline.probe]`):

| Key | Default | Meaning |
|---|---|---|
| `interval_secs` | `120` | probe cycle period; an upper bound — each cycle waits 70–100 % of it |
| `timeout_secs` | `10` | per-probe timeout |
| `max_concurrent` | `4` | concurrent probe tasks |
| `max_dials` | `2` | concurrent probe dials |
| `min_failures` | `3` | consecutive failures before the uplink is unhealthy; also the success streak required before auto-failback |
| `attempts` | `1` | attempts per uplink per cycle; each failed attempt increments the failure counter, a passing one resets it and increments the success counter. Values above 1 log a warning |
| `skip_when_active` | `true` | skip the cycle for an uplink that carried traffic recently (see below) |
| `liveness_interval_secs` | `300` | with `skip_when_active`, force one probe cycle at least this often; `0` disables |
| `endpoint_check` | `false` | bare-TCP reachability check of the uplink's endpoints (see below) |
| `endpoint_check_timeout_ms` | `2000` | per-endpoint deadline for `endpoint_check`, resolution included (minimum 100) |

`endpoint_check` connects to every endpoint of the uplink (primary + fallbacks, both planes, deduplicated by `host:port` plus egress options) concurrently. It only speeds up a verdict the regular probe already reached. When no endpoint accepts a connect and the probe got through on neither plane, the failure is treated as host-level: the uplink is marked unhealthy after `min_failures` such cycles without walking the carrier descent (`h3 → h2 → h1`) or rotating the wire chain, and the endpoint list appears in `last_error`. A switched-off host is then detected in a couple of cycles instead of several minutes. A probe that got through overrules the check: a bare connect cannot tell "the server is gone" from "new TCP is refused while traffic rides an established QUIC carrier".

The check runs after the probe, and only on cycles where the probe failed on every plane. Detection latency is the same as running it first, and a healthy uplink spends no extra connect per cycle. On the server each check is a TCP connection closed before any ClientHello; at `interval_secs = 10` that would be 8 640 per uplink per day per client. On dashboards, `probe="endpoint"` in `outline_ws_probe_runs_total` / `outline_ws_probe_duration_seconds` has a near-zero rate in steady state; a non-zero rate means uplinks are failing probes. Keep `endpoint_check_timeout_ms` well below `timeout_secs`: it is paid on top of a failed cycle, and a dead host costs the full deadline because a black-holed SYN never draws an RST.

Probe timing:

- Probes run on the `interval_secs` timer.
- When a runtime failure sets a new cooldown, the probe loop is woken immediately (internal `Notify`, at most once per 15 s per uplink and transport), so the failover is confirmed within one probe cycle instead of at the next scheduled one.
- Probe skip under traffic (`skip_when_active = true`, all routing scopes): the cycle is skipped for an uplink when TCP traffic was seen within the last `interval_secs`, the uplink is probe-healthy and no runtime cooldown is active. The probe still runs when a chunk-0 failure was seen recently (`chunk0_failure_window_secs`, default 300) or when `liveness_interval_secs` has passed since the last full cycle. An unhealthy uplink is always probed, since the probe is what restores it.

Warm-standby validation: every 15 s, standby connections are checked with a 1 ms non-blocking read. EOF, a close frame or an error clears the slot and refills it; a timeout (no data within 1 ms) means the connection is still open.

Probe activation:

- probes run only when probe settings are configured;
- `[outline.probe]` alone enables no check;
- at least one of `[outline.probe.ws]`, `.http`, `.dns`, `.tcp` or `.tls` must be present.

Uplinks without a `udp_ws_url` are TCP-only: no UDP health state or standby slots are created for them, and UDP probe outcomes do not affect their UDP health metric.

## IPv6

Supported:

- SOCKS5 IPv6 targets
- IPv6 literal upstream URLs such as `wss://[2001:db8::10]/SECRET/tcp`
- IPv6 probes
- IPv6 listeners
- IPv6 UDP packets in TUN mode
- IPv6 upstream transport for `h2` and `h3`

## TUN mode

The process attaches to an existing TUN device. Interface creation, addresses, routes and policy routing are configured outside the app.

### tun2udp

- IPv4 and IPv6 UDP forwarding
- IPv4 and IPv6 fragment reassembly on the TUN ingress path
- local IPv4 ICMP echo replies (`ping`)
- local ICMPv6 echo replies, with source fragmentation to the IPv6 minimum MTU when needed
- optional group-health gating of those replies (`tun_suppress_icmp_reply_when_down` on the uplink group): pings routed to a group are not answered while the group has no healthy uplink, so an external watchdog can detect a dead tunnel
- the gate also requires a fresh health verdict (`tun_icmp_liveness_window_secs`). The reply is generated locally — the ping never leaves the host — so answering it only proves this loop runs, and the `healthy` flag keeps its last value if the probe loop dies. With the window, some healthy uplink must also have carried traffic or completed a probe cycle inside it; otherwise the reply is withheld and counted as `icmp_reply_suppressed_stale`. Unset, the window is `max(3 × interval, liveness_interval + 60s, 60s)`; `0` checks the health flag only; groups without probes skip the freshness check
- IPv6 UDP and ICMPv6 across the supported extension-header paths
- per-flow uplink transport
- idle flow cleanup (`[tun] idle_timeout_secs`, default 300)
- flow count limit (`max_flows`, default 4096) with eviction of the least recently seen flow
- flow and packet-outcome metrics, including local ICMP replies

### tun2tcp

- userspace TCP relay over Outline TCP uplinks
- SYN / SYN-ACK / FIN / RST handling
- out-of-order buffering
- receive-window enforcement
- SACK-aware receive/send
- adaptive RTO
- zero-window persist/backoff
- bounded buffers and retransmit budget (`[tun.tcp] max_retransmits`, default 12)
- flow termination on timeout, overflow or relay failure
- transport errors feed the uplink penalty system: abrupt upstream closes (e.g. QUIC `APPLICATION_CLOSE` / `H3_INTERNAL_ERROR`) go to `report_runtime_failure`, so the H3→H2 downgrade and failure penalty apply to TUN TCP flows as they do to SOCKS5 flows; clean WebSocket closes (FIN or Close frame) are not failures

`tun2tcp` is not equivalent to a kernel TCP stack.

### IKE / IPsec NAT-T bypass

`tun.ipsec_bypass = true` sends UDP flows with destination port 500 or 4500 to the direct path (as `via = "direct"`), bypassing policy routing. VoWiFi and other IKEv2/IPsec clients then reach their gateway with ESP-in-UDP; raw ESP (IP protocol 50) is always dropped because the TUN classifier forwards only TCP/UDP/ICMP.

The bypass uses the direct path's local socket. On hosts where TUN holds the default route, that socket would loop back into TUN: on Linux set `direct_fwmark` and add a matching `ip rule fwmark <mark> lookup <table>`, where `<mark>` is the `direct_fwmark` value and `<table>` a routing table with the physical default route. Without `direct_fwmark` the process logs a warning at startup.

Default: `false`. Both ports are matched together: IKEv2 moves IKE_AUTH from 500 to 4500 mid-session via NAT_DETECTION, so bypassing only 4500 breaks the handshake.

### Carrier migration (surviving a dead carrier)

A tunnelled TUN flow does not own its transport: it shares one carrier — a single H3/H2/H1 connection — with the other flows on that uplink. When the carrier collapses (an H3 connection-level error takes down everything multiplexed on it at once), every flow on it loses its transport at the same moment, and each application sees its connection die.

The upstream sockets are still there. The server moves each one into its orphan registry, keyed by the Session ID it issued for that flow, and holds it for 30 s ([`docs/SESSION-RESUMPTION.md`](../outline-ss-rust/docs/SESSION-RESUMPTION.md)). With `[tun.tcp] carrier_migration = true` (the default), a flow whose carrier dies dials a new one, presents its own Session ID, gets the parked upstream re-attached, and closes the byte gap in both directions before continuing. The Ack-Prefix Protocol (v1) tells the client how many uplink bytes the server actually forwarded, so it replays only the tail lost in flight; Symmetric Downlink Replay (v2) returns the downstream bytes the dead carrier never delivered, and they are flushed to the application before anything from the new carrier. The application sees no disconnect: no FIN, no RST, no gap, no duplicate byte.

It engages only on a confirmed resume hit. A redial that presents an ID can miss — the park expired, or the server has resumption off — and on a miss the server opens a new upstream to the destination, with the byte stream starting from zero. Continuing the flow on that would splice a new stream onto a half-finished one and hand the application corrupt data that looks valid. So the client migrates only when the server proves the re-attach by sending the v1 control frame, which it sends only after the orphan was taken. The capability header on the upgrade response is not proof: the server echoes it on hit and miss alike. Everything else — a miss, a timeout, an unparseable frame, a replay the client can no longer reproduce byte-exact, a truncated downstream slice — falls through to the ordinary teardown.

Consequences:

- Server-side resumption is off by default (`[session_resumption] enabled` on outline-ss-rust). A server without it never issues a Session ID, so its flows are never eligible and the client setting has no effect there.
- Direct (`via = "direct"`) flows never migrate: they own a plain socket to the origin, there is no carrier to move off and nothing parked to re-attach.
- Limits: at most 2 attempts per flow, none started later than 20 s after the first (the server's park TTL is 30 s), and the uplink replay ring is capped at 64 KiB per flow. A flow that sends one chunk larger than that loses its ring, cannot prove byte-exactness, and tears down as before instead of resuming with a hole.
- The migration dial requests the uplink's configured carrier, not the capped one. The carrier death that triggers a migration is itself a runtime failure, which caps the uplink one rank down (`ws_h3` → `ws_h2`) for `mode_downgrade_secs`. Honouring that cap would put every rescued flow on TCP over TCP for the rest of its life — nothing moves a live flow back up — so a long download rescued from a dead H3 carrier would crawl instead of reconnecting at full speed. The dial still falls back `h3 → h2 → h1` on its own when the carrier is really broken. For the same reason the migration re-dials its own uplink rather than a re-selected one: the carrier death may have put that uplink in cooldown.
- Counters in `outline_ws_tun_tcp_events_total{event=…}`: `carrier_migrated`, `carrier_migration_miss`, `carrier_migration_dial_failed`, `carrier_migration_replay_evicted`, `carrier_migration_replay_ahead`, `carrier_migration_downlink_truncated`, `carrier_migration_downlink_frame_invalid`, plus one counter per reason a flow was ineligible before any dial: `carrier_migration_disabled`, `carrier_migration_abandoned`, `carrier_migration_no_session_id`, `carrier_migration_no_replay_ring`, `carrier_migration_budget_spent`, `carrier_migration_deadline_passed`. A flow blocked on a precondition never dials, so without these six "no migration was attempted" would look the same as "this build has no migration code".

`carrier_migration = false` restores the old behaviour: a dead carrier becomes a FIN/RST immediately.

#### Operator soft switch

The same mechanism carries live TUN TCP flows across an operator soft switch: `POST /control/activate {"group":"…","uplink":"…","soft":true}` on a group with `mode = "active_passive"` and `shared_resume = true`.

In strict `active_passive` a group has one active uplink, and a flow left on another one is closed with RST (`event="global_switch"`). A soft switch replaces that: the flow's upstream reader retires the old carrier and then dials the new active uplink with the flow's own Session ID. A mesh cluster shares one resume scope and the ID carries its home shard, so the new edge relays to the home node that parked the upstream and re-attaches it — same confirmed-hit rule, same v1/v2 replay, same no-FIN/no-RST/no-gap/no-duplicate result. Anything short of a confirmed hit falls through to the RST a hard switch would have sent.

The retire-then-redial order is required. Unlike a carrier death, the old carrier is healthy here, and the server parks an upstream only after that carrier has closed. A redial that arrived first would find the ID on a live session, get `miss-unknown`, and be given a new upstream — a guaranteed miss. Closing the carrier first puts the flow inside the server's park-before-resume barrier, which covers the remaining race. (For the same reason the client sends `X-Xhttp-Fin` on XHTTP carriers: they have no close signal of their own, and the idle sweep comes too late for a soft switch.)

- `soft` is honoured only on a `shared_resume` group. Elsewhere `/control/activate` turns it into a hard switch and reports the effective value in the response.
- Counters in `outline_ws_tun_tcp_events_total{event=…}`: `soft_switch_migrated` and `soft_switch_migration_failed` (the latter is followed by the ordinary `global_switch` teardown).

#### Which repoints migrate, and which abandon

What decides a stranded flow's fate is whether the switch means to abandon it, not who moved the pointer. The published snapshot carries a `SwitchIntent`:

| Intent | Set by | Live flows on the old uplink |
| --- | --- | --- |
| `OperatorHard` | `/control/activate {"soft":false}`, a hard scheduled reselect, or any soft request clamped off a cluster | RST (`global_switch`) |
| `OperatorSoft` | `/control/activate {"soft":true}` on a `shared_resume` group | migrate, falling back to RST |
| `Failover` | probe failover, runtime-failure failover, auto-failback, carrier-degraded failover, loss-driven failover, initial selection | migrate on a `shared_resume` group, else RST |

A hard switch abandons on purpose: under a mesh cluster a migrated session is relayed back to its home node, which is the node being drained, so migrating would defeat the drain. In a failover nobody decided the sessions should end, and the uplink it moved off is usually the unhealthy one — the parked upstream lives on the server, and the mesh reaches it from the new edge without the client's broken path. Without a cluster (`shared_resume = false`) nothing migrates: there is nothing parked to re-attach, so a dial would only add latency before the same teardown.

#### TUN UDP flows

The same verdict applies to tunnelled UDP flows, with one difference: there is no byte continuity to protect, so there is no confirmed-hit rule. A parked UDP session keeps no back-buffer of upstream-bound packets, so a resume miss costs a new exit source port — never a spliced byte stream, which is what makes the TCP path insist on proof.

A hit preserves the session: the server re-points the flow's parked NAT entries (SS-UDP) or re-attaches its pinned socket (VLESS-UDP), so the exit keeps the same source port and the peer's NAT binding, path validation and per-address state survive the switch. The flow's uplink task retires the old carrier — reader first, then the carrier, then the redial — for the same park-before-resume reason as TCP.

- Counters in `outline_ws_tun_udp_events_total{event=…}`: `soft_switch_migrated`, `soft_switch_migrated_no_resume_id` (the flow was carried over, but the server had issued no Session ID, so the exit source port changed), `soft_switch_migration_failed` (the redial failed; the flow is torn down as in a hard switch), `soft_switch_target_invalid`.
- Each tunnelled UDP flow, and each SOCKS5 UDP association, holds its own resume slot. TUN dials one carrier per flow; with the process-wide `<resume-scope>#udp` slot they used to share, a new flow presented the previous flow's parked ID, and a hit on that was a hit on another flow's session.

### TUN PMTUD safety gate

When the upstream transport refuses an oversize UDP datagram on the TUN path (SS-UDP, VLESS-UDP, SS-2022, …), the engine sends an ICMP "Fragmentation Needed" (IPv4) or "Packet Too Big" (IPv6) to the original sender so its PMTUD can react, at most one PTB per second per flow. `tun.pmtud_emit_below_quic_initial` decides whether that PTB may advertise a path MTU below QUIC v1's Initial-datagram minimum (1200 v4 / 1280 v6, RFC 9000 §14.1).

Default `false`: such PTBs are suppressed. QUIC stacks treat a PTB below the minimum as "this destination cannot carry QUIC" and fall back to TCP; with the gate, QUIC traffic (YouTube, Google services) stays on UDP even when the TUN uplink's per-datagram budget is slightly below 1200 bytes. The oversize drop is absorbed and the sender's own retransmit/timeout logic adjusts.

`tun.pmtud_emit_below_quic_initial = true` emits the PTB unconditionally. Use it where pushing QUIC to TCP does not matter and the PMTUD signal on every drop does — e.g. a VoWiFi / IKEv2 concentrator carrying IKE_AUTH with certificates over a narrow uplink, where the PTB is the only way for the IKE retransmit loop to learn the tunnel MTU. Full contract: [docs/TUN-PMTUD.md](docs/TUN-PMTUD.md).

## Linux fwmark

Per-uplink `fwmark` sets `SO_MARK` on outbound sockets:

- HTTP/1.1 WebSocket TCP sockets
- HTTP/2 WebSocket TCP sockets
- HTTP/3 QUIC UDP sockets
- probe dials
- warm-standby connections

Requirements:

- Linux only
- `CAP_NET_ADMIN`
- under systemd, `PrivateUsers=no`: `setsockopt(SO_MARK)` is checked against the user namespace that owns the network stack (the init namespace). With `PrivateUsers=true` the capability applies only inside the private namespace and every marked dial fails with `EPERM`. This applies to per-uplink `fwmark` and to top-level `direct_fwmark`.

## Metrics

The multi-instance dashboard is not part of this binary. It is served by the `outline-ui` service, which aggregates the control API of every instance; see [`bins/outline-ui/README.md`](../outline-ui/README.md). This binary exposes the read-only metrics endpoint and the authenticated control plane.

With `[metrics]` configured, the process serves:

- `/metrics` — Prometheus text exposition

```bash
curl http://[::1]:9090/metrics
```

The metrics listener has no mutating endpoints; `/switch` and the rest live on the separate, authenticated control listener, so read access to metrics does not allow switching the active uplink.

Prometheus scrape example:

```yaml
scrape_configs:
  - job_name: outline-ws-rust
    metrics_path: /metrics
    static_configs:
      - targets:
          - "[::1]:9090"
```

Metric groups:

- build and startup info
- process resident memory and heap gauges
- SOCKS5 requests and active sessions, including `command="connect"`, `command="udp_associate"` and `command="udp_in_tcp"`
- session duration histogram
- payload bytes and UDP datagrams
- oversized UDP drops in both directions
- uplink health, latency, EWMA RTT, penalties, score, cooldown, standby readiness. `uplink_health` is `1` (healthy) or `0` (unhealthy) only after a probe has confirmed a state; before the first probe cycle the series is absent, which means "unknown", not unhealthy.
- routing policy and active-uplink selection state
- probe results and latency
- warm-standby acquire and refill outcomes
- TUN flow and packet metrics
- `tun2tcp` retransmit, backlog, window, RTT and RTO metrics

On Linux the process memory sampler updates:

- `outline_ws_process_resident_memory_bytes`
- `outline_ws_process_virtual_memory_bytes`
- `outline_ws_process_heap_allocated_bytes`
- `outline_ws_process_heap_mode_info{mode}`
- `outline_ws_process_open_fds`
- `outline_ws_process_threads`

With the default `jemalloc` feature the heap values come from jemalloc's own counters (`stats.allocated` / `stats.resident`) and `heap_mode_info{mode="exact"}` is `1`. Builds without jemalloc estimate the heap from `VmData` (`mode="estimated"`); non-Linux builds report `mode="unavailable"`.

On Linux the process also logs a periodic descriptor inventory, `process fd snapshot`: total open FDs plus a breakdown into sockets, pipes, anon inodes, regular files and other types.

`outline_ws_selection_mode_info{mode}`, `outline_ws_routing_scope_info{scope}`, `outline_ws_global_active_uplink_info{uplink}` and `outline_ws_sticky_routes` expose selector configuration and active-uplink state.

`outline_ws_group_bypass_active{group, transport}` reports the `bypass_when_down` state: `1` while new flows of that transport go direct because the group has no healthy uplink, `0` while traffic tunnels. The series exists only for groups with `bypass_when_down = true`. The outline-ui dashboard shows the same state as a group-header chip (`bypass armed` / `bypass: direct`); the Grafana dashboard has the panels "Direct Bypass (bypass_when_down)" and "Direct Bypass Timeline" in the Routing Policy section.

Per-uplink open-connection accounting, for connections that leak into a non-active uplink after a `global` / `per_uplink` switch:

- `outline_ws_uplink_open_connections{group, transport, uplink}` — gauge of open upstream transports per uplink. After a switch the new active uplink ramps up while the old one drains; a series that does not drain is the leak signal.
- `outline_ws_uplink_connection_close_total{group, transport, uplink, classification}` — counter of upstream-transport closes, classified at close time as `active` (the uplink was still active), `inactive` (the active pointer had moved — a stranded session draining) or `unknown` (`per_flow` scope, no active pointer). `rate(...{classification="inactive"}[5m])` is the drain rate after a switch; a sustained non-zero rate outside a recent switch points at a stale sticky route or warm-standby pool.

Both feed the Grafana row "Inactive Uplink Leak (Global / Per-Uplink)" in `grafana/outline-ws-rust-dashboard.json`. Probe connections are not counted; the metrics cover user-traffic dials only.

`outline_ws_carrier_writer_terminations_total{writer, reason}` counts WebSocket carrier writer tasks that stopped because a sink write failed. `writer` is `ss` (SS over WS) or `frame` (VLESS byte-chunk / datagram writer); `reason` is `peer_closed` when the carrier was already closed (routine, logged at `debug`) or `error` for a real write failure (logged at `warn`). A sustained `reason="error"` rate means the uplink is failing writes. Grafana row: "Carrier Writer Terminations".

Further counters:

- `outline_ws_tun_udp_forward_errors_total{reason}` — TUN UDP packets that could not be delivered upstream: `all_uplinks_failed`, `transport_error`, `connect_failed`, `other`.
- `outline_ws_udp_oversized_dropped_total{direction="up|down", cause}` — oversized UDP packets dropped before uplink forwarding (`up`) or before client delivery (`down`); `cause` is `socks_client`, `socks_relay`, `socks_direct`, `socks_in_tcp`, `ss_socket`, `vless_udp` or `xhttp_records`.
- `outline_ws_udp_malformed_dropped_total{cause}` — client datagrams the SOCKS5 UDP ingress cannot decode, dropped one by one while the association keeps running: `parse` (malformed SOCKS5 UDP header or unsupported address type), `reassembly` (fragment sequence out of order, target changed, or over the reassembly cap).
- `outline_ws_uplink_payload_integrity_errors_total{transport, group, uplink, cause}` — downlink datagrams that fail payload integrity: `decrypt_failed`, `packet_too_short`, `udp_out_of_order` (SS2022 replay/reorder). Kept separate from `outline_ws_uplink_runtime_failures_total`: a corrupt payload says something about the bytes, not the carrier, so it causes no cooldown, no penalty, no runtime-failure streak and no carrier downgrade (`xhttp_h3 → xhttp_h2`). Only the affected flow is closed: on the TUN UDP path with reason `payload_error` (recreated on the next packet); on the SOCKS5 UDP downlink the datagram is dropped and the association keeps its transport. When these were charged to the carrier, a production uplink spent 69.6 % of the time on UDP over TCP at a ~0.1 % corrupt-datagram rate. A rising rate is still a defect past the carrier; watch it on its own panel, not in the failover graph.
- `outline_ws_tun_icmp_local_replies_total{ip_family}` — local ICMP echo replies.

On the TUN UDP path oversize drops also produce an ICMP PTB toward the sender; see [TUN PMTUD safety gate](#tun-pmtud-safety-gate) and [docs/TUN-PMTUD.md](docs/TUN-PMTUD.md).

Grafana dashboards (see [`grafana/README.md`](grafana/README.md)):

- [`grafana/outline-ws-rust-dashboard.json`](grafana/outline-ws-rust-dashboard.json)
- [`grafana/outline-ws-rust-hang-diagnostics.json`](grafana/outline-ws-rust-hang-diagnostics.json)

## Control plane

With `[control]` configured, the process serves mutating endpoints on a separate TCP listener that requires a bearer token:

| Method and path | Purpose |
|---|---|
| `GET /control/topology` | instance / group / uplink topology for dashboards |
| `GET /control/summary` | compact group / uplink health counters |
| `POST /control/activate` | JSON activation API (dashboard click actions) |
| `POST /control/reselect` | weighted-random re-selection of a group's strict active uplink now — the rotation `reselect_at` / `reselect_interval` run on schedule. Body `{"group":"main","soft":true}` (`soft` defaults to `true`) |
| `POST /control/uplink_enabled` | administratively enable/disable an uplink. Body `{"group":"main","uplink":"backup","enabled":false}`. A disabled uplink is excluded from probing, candidate selection, failover and standby refill until re-enabled; if it was active, traffic fails over to an enabled uplink immediately. Not persisted: after a restart every uplink is enabled. The outline-ui dashboard shows it as the per-uplink power button (Enable / Disable) |
| `GET` / `POST` / `PATCH` / `DELETE /control/uplinks`, `POST /control/uplinks/reorder` | stage `[[outline.uplinks]]` edits in the config file |
| `GET` / `POST` / `PATCH` / `DELETE /control/uplink_groups`, `POST /control/uplink_groups/reorder` | stage `[[uplink_group]]` edits in the config file (see "`/control/uplink_groups` (CRUD)" in [docs/UPLINK-CONFIGURATIONS.md](docs/UPLINK-CONFIGURATIONS.md)) |
| `GET` / `POST` / `PATCH` / `DELETE /control/routes`, `POST /control/routes/reorder` | stage `[[route]]` edits; reorder moves a rule within the first-match-wins list |
| `GET` / `PATCH /control/config` | read and modify client subsystem settings in the config file (`[probe]`, `[socks5]`, `[tun]`, `[dial]`, `[padding]`, `[quic]`, `[h2]`, `[tcp_timeouts]`, `fingerprint_profile`, `prefer_public_ipv6_src`, `direct_fwmark`). Returns `{ "status": "ok", "apply_required": true, "restart_required": bool }`. Before writing, `PATCH` loads the patched file the way startup does; if it would not load (for example `tun.mtu` below 1280 or `dial.timeout_secs = 0`), the request gets `400` with the loader's error and the file on disk is left unchanged |
| `POST /control/apply` | hot-apply staged uplink and group edits, and staged route edits when routing was configured at startup, without a restart |
| `GET /control/alloc` | allocator statistics (jemalloc counters in the default build) |
| `POST /switch` | manual active-uplink override |

Requests without a matching `Authorization: Bearer <token>` header are rejected with `401 Unauthorized` before the body is read; there is no anonymous access.

### Configuration

Configure `listen` and a token in `[control]`, or pass `--control-listen` (`CONTROL_LISTEN`) together with `--control-token` (`CONTROL_TOKEN`). The token can also come from a file via `token_file = "..."` (path relative to the config file). Setting only one of the two halves is a startup error.

Bind the control listener to loopback or a management VLAN; the token does not replace network-level isolation.

### Manual uplink switch

`POST /switch` pins the active uplink of an `active_passive` group without waiting for the probe loop. The selection is persisted via the state store (when configured) and survives restarts.

Query parameters:

- `uplink` (required) — uplink name to activate.
- `group` (optional) — target group. When omitted, all groups are searched (uplink names are globally unique).
- `transport` (optional) — `tcp`, `udp` or `both` (default). Used only with `routing_scope = per_uplink`; ignored under `global`.

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

Responses: `200` on success; `400` when the uplink/group is unknown or the group is not in `active_passive` mode; `401` when the bearer token is missing or wrong; `405` for non-POST methods. The override holds while the chosen uplink is healthy; when the probe loop marks it unhealthy, normal failover takes over. With `auto_failback = true` the loop may return to a higher-priority uplink once it is stable.

### Control API for dashboards

`GET /control/topology` returns groups and uplinks as JSON, including the booleans `active_global`, `active_tcp`, `active_udp` per uplink, for the outline-ui dashboard or other control clients.

`GET /control/summary` returns counters: `groups_total`, `uplinks_total`, healthy/unhealthy TCP/UDP counts and active-selection counters.

`POST /control/activate` takes JSON and uses the same switching logic as `/switch`:

```json
{
  "group": "core",
  "uplink": "uplink-02",
  "transport": "tcp"
}
```

`POST /control/reselect` runs the weighted-random re-selection that `reselect_at` / `reselect_interval` perform, outside their schedule. It applies to an `active_passive` group with a single strict active slot (`global` or `per_uplink` scope); other groups return `outcome: "skipped"`.

```json
{
  "group": "main",
  "soft": true
}
```

`soft` defaults to `true` and requests a session-preserving switch via cluster resume; on a group without `shared_resume` it becomes a hard switch, as in `/control/activate`. The response reports the effective `soft` value, plus `from` / `to` uplink names when the slot moved:

```json
{
  "group": "main",
  "outcome": "switched",
  "from": "uplink-01",
  "to": "uplink-02",
  "soft": true
}
```

`outcome` is `switched`, `no_candidate` (no eligible uplink left after excluding the current active and disabled / unhealthy / cooldown uplinks) or `skipped` (the group is not `active_passive` or has no single strict active slot). The outline-ui dashboard shows it as the per-group **Reselect** button; unlike the soft switch, it is offered whether or not `cluster_resume_enabled` is set.

`/control/uplinks` edits the `[[outline.uplinks]]` array in the TOML file on disk. Mutation responses include `apply_required: true` when `/control/apply` can activate the staged change; `restart_required` is reserved for changes that cannot be hot-applied.

`/control/routes` edits the `[[route]]` array the same way, but by array index rather than name (a rule has no identity key), guarded by an optimistic-concurrency `revision`: a stale index from a concurrent edit is rejected instead of moving the wrong rule. `POST /control/routes/reorder` moves one rule to a new index, since first-match-wins evaluation depends on order. `POST /control/apply` hot-applies a staged route edit like an uplink edit, but only when `[[route]]` was present at process start. Enabling policy routing on a node that started without it (everything through the first group) needs a restart, because there is no live routing table to swap.

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

## Production operations

### `install-client.sh`

[install-client.sh](../../install-client.sh) installs the client on Linux x86-64 or AArch64 from GitHub releases. Run it as `root` on the target host:

```bash
curl -fsSL https://raw.githubusercontent.com/balookrd/outline-proxy/main/install-client.sh -o install-client.sh
chmod +x install-client.sh
./install-client.sh --help
sudo ./install-client.sh
```

Modes:

```bash
sudo ./install-client.sh                       # latest stable release (newest ws-v* tag)
sudo ./install-client.sh --force               # reinstall even if the version matches
sudo CHANNEL=nightly ./install-client.sh       # rolling ws-nightly prerelease
sudo VERSION=v1.2.3 ./install-client.sh        # pin a stable version (tag ws-v1.2.3)
sudo ./install-client.sh --remove              # alias --uninstall
sudo ./install-client.sh --purge
```

What the script does:

- picks the release asset for `uname -m` (`x86_64`/`amd64` → `x86_64-unknown-linux-musl`, `aarch64`/`arm64` → `aarch64-unknown-linux-musl`); other architectures are rejected
- skips the download when the installed version already matches the selected release (`--force` or `FORCE=1` overrides); for the nightly channel it tracks the release commit SHA in `/etc/outline-ws-rust/nightly-commit`
- installs the binary to `/usr/local/bin/outline-ws-rust`, keeping the previous one as `<path>.bak.<timestamp>`
- installs `outline-ws-rust.service` and `outline-ws-rust@.service` into `/etc/systemd/system`, taken from the same release tag as the binary
- creates the system user and group `outline-ws`, the directories `/etc/outline-ws-rust` and `/var/lib/outline-ws-rust`, and gives the config directory to `outline-ws` (`0750`, files `0640`) so the control API can write the config
- downloads `config.toml` and `instances/example.toml` only if they do not exist yet
- restarts only `outline-ws-rust` units that were active; it does not enable or start a fresh service, and a stopped service stays stopped

After the first install:

1. Edit `/etc/outline-ws-rust/config.toml`.
2. Enable one variant:
   - single instance: `sudo systemctl enable --now outline-ws-rust.service`
   - named instance (config `/etc/outline-ws-rust/instances/<name>.toml`): `sudo systemctl enable --now outline-ws-rust@<name>.service`
3. Check the status: `systemctl status outline-ws-rust --no-pager`.
4. Check the logs: `journalctl -u outline-ws-rust -e --no-pager`.

Re-run the script to upgrade; it replaces the binary only when the selected release differs from the installed one.

Environment overrides:

| Variable | Default | Meaning |
|---|---|---|
| `CHANNEL` | `stable` | `stable` or `nightly` |
| `VERSION` | latest | stable: `1.2.3` or `v1.2.3`; with `CHANNEL=nightly` only `nightly` is accepted |
| `FORCE` | empty | `1` reinstalls even if the version matches |
| `INSTALL_PATH` | `/usr/local/bin/outline-ws-rust` | full path of the installed binary |
| `CONFIG_DIR` | `/etc/outline-ws-rust` | configuration directory |
| `STATE_DIR` | `/var/lib/outline-ws-rust` | state directory |
| `SERVICE_USER` / `SERVICE_GROUP` | `outline-ws` | system user and group of the service |
| `GITHUB_TOKEN` | empty | GitHub token against API rate limits |

Removal:

- `--remove` (alias `--uninstall`): stops and disables `outline-ws-rust.service` and every `outline-ws-rust@<name>.service`, removes both unit files (followed by `daemon-reload`), the binary and its `.bak.*` backups. Keeps `/etc/outline-ws-rust` (including `instances/`), `/var/lib/outline-ws-rust` and the `outline-ws` user/group, so a reinstall reuses the config.
- `--purge`: everything `--remove` does, plus deletes `/etc/outline-ws-rust`, `/var/lib/outline-ws-rust` and the `outline-ws` user/group.

Both modes are idempotent: missing artifacts are skipped.

#### Installing through an HTTP(S) proxy

If `github.com` or its release CDN (`objects.githubusercontent.com`) is unreachable from the host, run the install through an HTTP or SOCKS5 proxy that can reach GitHub; `curl` in the script honours the standard proxy variables.

`sudo` drops `http_proxy` / `https_proxy` by default, so pass them explicitly:

```bash
sudo https_proxy=http://HOST:PORT http_proxy=http://HOST:PORT ./install-client.sh
```

or export them and use `sudo -E`:

```bash
export https_proxy=http://HOST:PORT
export http_proxy=http://HOST:PORT
sudo -E ./install-client.sh
```

For SOCKS5 (e.g. an `ssh -D 1080 user@vps` tunnel) use `ALL_PROXY=socks5h://HOST:PORT`. Authenticated proxies use `http://USER:PASS@HOST:PORT` (URL-encode special characters in the password).

Check the proxy before running the installer:

```bash
curl -v --proxy http://HOST:PORT --max-time 20 https://github.com -o /dev/null
```

### systemd

Units:

- [`systemd/outline-ws-rust.service`](systemd/outline-ws-rust.service) — single instance, config `/etc/outline-ws-rust/config.toml`, state in `/var/lib/outline-ws-rust/_default/`
- [`systemd/outline-ws-rust@.service`](systemd/outline-ws-rust@.service) — named-instance template, config `/etc/outline-ws-rust/instances/<name>.toml`, state in `/var/lib/outline-ws-rust/<name>/`

Manual installation (`install-client.sh` does the same):

1. Install the binary to `/usr/local/bin/outline-ws-rust`.
2. Create the service user and group:
   `sudo groupadd --system outline-ws && sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid outline-ws outline-ws`
3. Install the configuration to `/etc/outline-ws-rust/config.toml` and give the directory to the service user:
   `sudo chown -R outline-ws:outline-ws /etc/outline-ws-rust && sudo chmod 0750 /etc/outline-ws-rust`
4. Copy both unit files to `/etc/systemd/system/`.
5. Reload and enable the service:
   `sudo systemctl daemon-reload && sudo systemctl enable --now outline-ws-rust`

What the units set:

- `Restart=on-failure`, `RestartSec=3s`
- `RUST_LOG=info`, logs to journald
- `LimitNOFILE=1048576`, `LimitSTACK=8M`, `TasksMax=infinity`
- `MemoryHigh=70%`, `MemoryMax=85%`: on a low-RAM host a burst of flows can exhaust memory faster than the kernel reclaims it and hang the whole host; with the limits the kernel OOM-kills the service and systemd restarts it. Override with a drop-in for fixed values
- `User=outline-ws` / `Group=outline-ws` with `StateDirectory=outline-ws-rust/_default` (template: `outline-ws-rust/%i`), so state files keep a stable owner
- `ReadWritePaths` includes `/etc/outline-ws-rust` (template: `/etc/outline-ws-rust/instances`) so control-API edits and config migration can write the file
- `AmbientCapabilities=CAP_NET_ADMIN` for `fwmark`; remove both capability lines if `fwmark` / `direct_fwmark` are not used. Using them also requires `PrivateUsers=no` in a drop-in: the units set `PrivateUsers=true`, and `SO_MARK` fails with `EPERM` inside a private user namespace even with the capability
- `PrivateDevices=false` for access to `/dev/net/tun` (TUN mode)
- `ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service` and the other `Protect*` / `Restrict*` options in the unit file

Thread stacks: Tokio worker and blocking threads use 2048 KiB stacks by default instead of inheriting the host's stack limit (`--thread-stack-size-kb` / `THREAD_STACK_SIZE_KB`). The single-instance unit sets `THREAD_STACK_SIZE_KB=512`; if a native resolver or deep FFI call overflows that, the process crashes at startup — raise the value.

### Logging

The service logs through `tracing`; the bundled units set `RUST_LOG=info`. Use `debug` only for troubleshooting: connection lifecycle and transport events become much more verbose.

Carrier lifecycle lines are emitted on the `outline_transport::conn_life` target in pairs: every `… connection opened` has exactly one `… connection closed` at the same level, with `id`, `peer`, `mode`, `age_secs`, `streams` and a `class`. A connection torn down locally (a probe released after its measurement, a cached carrier whose last stream ended) is reported by the connection's own drop guard as `class=local_drop`; the driver task that watches for a protocol-level close is cancelled on drop and cannot report it. Because the pairs balance, a descriptor leak shows up as a gap between the two counts. Before the pairing, `opened` vs `closed` read 34 515 vs 0 on a busy node and looked exactly like a leak.

Shared (cached) carriers log the pair at `info`; probe connections — one dial per measurement, tens of thousands a day — log it at `debug`.

Two routine events are logged below `warn` because neither indicates a problem in this process: a WS writer task stopping because its carrier was already closed (counted by `outline_ws_carrier_writer_terminations_total{reason="peer_closed"}`), and an HTTP client hanging up on the metrics / control listener before its request completed (`request aborted by client`). Real write failures and request failures stay at `warn`.

### Security notes

- Do not expose `metrics.listen` without access control.
- Restrict `control.listen` further: bind it to loopback or a management network, treat the bearer token as a credential (rotate it, store it outside the config via `token_file`), and never reuse the metrics port for it. The control listener is the only path that can change the active-uplink selection.
- Built-in listener limits against slowloris / idle connections (compiled in, not configurable):

  | Listener | Max concurrent connections | Timeout |
  |---|---|---|
  | SOCKS5 | 4096 | 10 s for the SOCKS5 handshake |
  | `/metrics` | 64 | 5 s to read request headers |
  | control | 16 | 5 s to read request headers; the bearer check runs only after the headers arrive, so this timeout is what stops unauthenticated peers from holding sockets |

- HTTP/3 carriers need UDP reachability to the server port.
- `fwmark` works only on Linux and requires `CAP_NET_ADMIN` or root; under a systemd sandbox with a private user namespace it also requires `PrivateUsers=no`.
- TUN mode needs access to `/dev/net/tun` (`PrivateDevices=false`).

## Testing

From the workspace root:

```bash
cargo check -p outline-ws-rust
cargo test -p outline-ws-rust
```

The CI gate (fmt, clippy, tests, feature matrix) is described in the root [`AGENTS.md`](../../AGENTS.md). End-to-end tests against real `outline-ss-rust` processes (`tests/e2e_*.rs`) run only with `RUN_E2E_FAILOVER=1`, and the TLS/H3 carrier set needs the `test-tls` feature:

```bash
RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1
```

Manual tests against a real server exist for HTTP/1.1, HTTP/2 and HTTP/3 (`real_server_h1`, `real_server_h2`, `real_server_h3`); each is skipped unless its `RUN_REAL_SERVER_*` variable is `1`:

```bash
RUN_REAL_SERVER_H2=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test -p outline-ws-rust --test real_server_h2 -- --nocapture
```

```bash
RUN_REAL_SERVER_H3=1 \
OUTLINE_TCP_WS_URL='wss://example.com/SECRET/tcp' \
OUTLINE_UDP_WS_URL='wss://example.com/SECRET/udp' \
SHADOWSOCKS_PASSWORD='Secret0' \
cargo test -p outline-ws-rust --test real_server_h3 -- --nocapture
```

Group isolation, fallback and direct dispatch:

```bash
cargo test -p outline-ws-rust --test group_routing -- --nocapture
```

Warm standby:

```bash
cargo test -p outline-ws-rust --test standby_validation -- --nocapture
```

## Protocol references

- [Outline `outline-ss-server`](https://github.com/Jigsaw-Code/outline-ss-server)
- [`hev-socks5-core`](https://github.com/heiher/hev-socks5-core)
- [`hev-socks5-tunnel`](https://github.com/heiher/hev-socks5-tunnel)
- [Shadowsocks AEAD specification](https://shadowsocks.org/doc/aead.html)
- [RFC 8441: Bootstrapping WebSockets with HTTP/2](https://datatracker.ietf.org/doc/html/rfc8441)
- [RFC 9220: Bootstrapping WebSockets with HTTP/3](https://datatracker.ietf.org/doc/html/rfc9220)

## Local patch tracking

Patches to vendored crates (`vendor/h3`, `vendor/sockudo-ws`, `vendor/quinn-proto`, `vendor/rustls`, `vendor/hyper`) are listed in the workspace-wide [`PATCHES.md`](../../PATCHES.md), including the `h3` patch used for RFC 9220.
