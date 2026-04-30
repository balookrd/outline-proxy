<p align="center">
  <img src="docs/logo.png" alt="outline-ws-rust" width="320">
</p>

# outline-ws-rust

`outline-ws-rust` is a production-oriented Rust proxy that accepts local SOCKS5 traffic and forwards it to Outline-compatible WebSocket transports over HTTP/1.1, HTTP/2, or HTTP/3, to direct Shadowsocks socket uplinks, to VLESS-over-WebSocket uplinks, or to raw QUIC uplinks (Shadowsocks / VLESS framed directly over QUIC streams and datagrams).

It supports:

- SOCKS5 `CONNECT`
- SOCKS5 `UDP ASSOCIATE` and `hev-socks5` `UDP-in-TCP` (`CMD=0x05`)
- multi-uplink failover and load balancing
- WebSocket-over-HTTP/1.1, RFC 8441 (`ws-over-h2`), and RFC 9220 (`ws-over-h3`)
- raw QUIC transport (per-ALPN: `vless`, `ss`, `h3`) — VLESS / Shadowsocks framed directly over QUIC bidi streams and datagrams (RFC 9221), no WebSocket / no HTTP/3
- VLESS-over-WebSocket uplinks (UUID auth, shared WSS dial path, per-destination UDP session-mux)
- direct Shadowsocks TCP/UDP socket uplinks
- Prometheus metrics, built-in multi-instance dashboard, and packaged Grafana dashboards
- existing TUN device integration for `tun2udp`
- stateful `tun2tcp` relay with production-oriented guardrails

---

*Русская версия: [README.ru.md](README.ru.md)*

## Overview

At a high level, the process does five jobs:

1. Accepts local SOCKS5 and optional TUN traffic.
2. Selects the best available uplink using health probes, EWMA RTT scoring, sticky routing, hysteresis, penalties, and warm standby.
3. Connects to an Outline WebSocket transport using the requested mode (`http1`, `h2`, or `h3`) with automatic fallback, to a raw QUIC uplink (`quic`; pairs with the matching ALPN-keyed listener on the server, falls back to WS over H2 → H1 on dial / handshake failure), or to a direct Shadowsocks socket / VLESS-over-WebSocket uplink.
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
        QC["Raw QUIC connectors
ALPN: vless / ss"]
        DS["Direct Shadowsocks
TCP / UDP socket"]
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
    LB -->|"*_ws_mode = quic"| QC
    LB -->|"transport = shadowsocks"| DS
    WS -->|"outline"| SS
    WS -->|"vless"| VL
    QC -->|"transport = websocket"| SS
    QC -->|"transport = vless"| VL

    subgraph Upstream["Upstream uplinks"]
        O1["outline-over-ws (A/B)"]
        O2["raw-quic edge (vless / ss)"]
        O3["direct shadowsocks edge"]
        O4["vless-over-ws edge"]
    end

    SS --> O1
    SS --> O2
    DS --> O3
    VL --> O4
    VL --> O2

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

### Outline transports

- `ws://` and `wss://`
- HTTP/1.1 Upgrade
- RFC 8441 WebSocket over HTTP/2
- RFC 9220 WebSocket over HTTP/3 / QUIC
- raw QUIC (per-ALPN, no WebSocket / no HTTP/3): selected via `*_ws_mode = "quic"`. ALPN `vless` carries VLESS-TCP (one bidi per session) and VLESS-UDP (per-target control bidi + datagrams demuxed by 4-byte server-allocated `session_id`). ALPN `ss` carries Shadowsocks-TCP (one bidi per session) and Shadowsocks-UDP (1 datagram = 1 SS-AEAD packet, RFC 9221). Multiple sessions of the same ALPN to the same `host:port` share one cached QUIC connection. Auxiliary ALPNs `vless-mtu` / `ss-mtu` carry oversized UDP packets that exceed the QUIC datagram limit on a server-initiated bidi. On dial / handshake failure, raw-QUIC paths fall back to WS over H2 (then H1) and open the H3-downgrade window so subsequent dials skip QUIC until the recovery probe confirms QUIC is reachable again.
- VLESS-over-XHTTP (`vless_mode = "xhttp_h2"` or `"xhttp_h3"`): pairs with the `xhttp_path_vless` listener on outline-ss-rust. The dial URL `vless_xhttp_url` selects the wire mode through its query string — bare URL or `?mode=packet-up` runs the GET + sequenced POSTs pair, `?mode=stream-one` runs a single bidirectional POST (h2 / h3 only). Useful when WebSocket upgrades are blocked on the path (Cloudflare-style CDNs, captive-portal middleboxes).
- direct Shadowsocks TCP/UDP socket uplinks
- VLESS-over-WebSocket uplinks (`transport = "vless"`, UUID auth, shared WSS dial path with `websocket`, per-destination UDP session-mux bounded by `vless_udp_max_sessions`)
- transport fallback:
  - `h3 -> h2 -> http1`
  - `h2 -> http1`
  - `quic -> h2 -> http1` on dial / handshake failure, with a per-uplink mode-downgrade window (governed by `h3_downgrade_secs`, also accepted as `mode_downgrade_secs`) so subsequent dials skip QUIC until the recovery probe confirms it again
  - `xhttp_h3 -> xhttp_h2` on dial failure, carrying the same `X-Outline-Resume` token across the carrier switch so a feature-enabled outline-ss-rust server re-attaches the parked VLESS upstream instead of opening a fresh one
- cross-transport client-side session resumption: WebSocket Upgrades carry `X-Outline-Resume-Capable: 1`; the server-issued `X-Outline-Session` ID is cached per uplink (and per (uplink, target) inside the VLESS UDP mux) and presented as `X-Outline-Resume: <hex>` on the next on-demand dial so a feature-enabled outline-ss-rust server can re-attach the parked upstream and skip the connect-to-target. Covers TCP-WS, SS-UDP-WS, VLESS-TCP raw QUIC (via Addons opcodes), VLESS-UDP raw QUIC, and VLESS-over-XHTTP (h2 and h3, packet-up and stream-one alike — the token round-trips on the same response that delivers the first downlink chunk). Opt-in on the wire and zero-overhead when the server doesn't support it.

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
  - `active_passive`: keep the current selected uplink until it becomes unhealthy or enters cooldown
- routing scope:
  - `per_flow`: decisions are made independently per routing key / target
  - `per_uplink`: one active uplink is shared process-wide per transport (`tcp` and `udp`); in `active_passive` mode the pinned TCP and UDP uplinks do not expire with `sticky_ttl`, established SOCKS TCP tunnels stay pinned to the uplink that completed setup while non-migratable flows that still depend on the older active uplink may be reselected or closed after a switch, and penalty history is not folded into the strict per-transport score
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
- hardened systemd unit
- Linux `fwmark` / `SO_MARK`
- IPv6-capable listeners, upstreams, probes, and SOCKS5 targets

## Current Limits

The project is intentionally practical, but there are still boundaries:

- `tun2tcp` is production-oriented but still not a kernel-equivalent TCP stack.
- Non-echo ICMP traffic on TUN is not supported.
- `probe.http` supports `http://` only, not `https://`. `probe.tcp` should target a speak-first TCP service such as SSH or SMTP, not a typical HTTP/HTTPS port.
- TCP failover is safe before useful payload exchange; live established TCP tunnels cannot be migrated transparently between uplinks.

## Repository Layout

- [`config.toml`](config.toml) - example configuration
- [`config-router.toml`](config-router.toml) - example router configuration
- [`systemd/outline-ws-rust.service`](systemd/outline-ws-rust.service) - hardened systemd unit
- [`grafana/outline-ws-rust-dashboard.json`](grafana/outline-ws-rust-dashboard.json) - main operational dashboard
- [`grafana/outline-ws-rust-tun-tcp-dashboard.json`](grafana/outline-ws-rust-tun-tcp-dashboard.json) - `tun2tcp` dashboard
- [`grafana/outline-ws-rust-native-burst-dashboard.json`](grafana/outline-ws-rust-native-burst-dashboard.json) - startup and traffic-switch burst diagnostics for native Shadowsocks mode
- [`src/bootstrap/`](src/bootstrap) - startup sequence: listener binding and persistent state store
- [`src/config/`](src/config) - configuration loading, schema, and validated types
- [`src/proxy/`](src/proxy) - SOCKS5 TCP/UDP ingress handlers (dispatcher, TCP failover, UDP relay)
- [`crates/outline-uplink/`](crates/outline-uplink) - uplink selection, probing, failover, and standby management
- [`crates/outline-transport/`](crates/outline-transport) - WebSocket / HTTP-2 / HTTP-3 / raw-QUIC / VLESS / direct-Shadowsocks transports + the cross-transport `ResumeCache`
- [`crates/outline-net/`](crates/outline-net) - DNS cache and shared net plumbing extracted from `outline-transport`
- [`crates/outline-ss2022/`](crates/outline-ss2022) - Shadowsocks 2022 framing helpers
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
cargo release-router-musl-arm
cargo release-router-musl-armv7
cargo release-router-musl-aarch64
```

### CI Releases

- Every push to `main` triggers the `Nightly Release` workflow.
- That workflow moves the rolling tag `nightly` to the current `main` commit and republishes the `Nightly` GitHub prerelease.
- Nightly publishes server `release` artifacts for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, router `release-router` artifacts for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, plus `SHA256SUMS.txt`.
- Nightly server archives are named `outline-ws-rust-vnightly-<full-commit-sha>-<target>.tar.gz`; router archives use `outline-ws-rust-router-vnightly-<full-commit-sha>-<target>.tar.gz`.
- To cut a stable release, run the manual `Release` workflow and pass `major_minor` such as `1.7`.
- CI finds the latest `v1.7.*` tag, increments the patch automatically, updates `Cargo.toml` and `Cargo.lock`, creates a release commit, and pushes that commit to `main`.
- After the release commit lands on `main`, create and push a signed tag locally; the tag push triggers the `Tag Release` workflow, which builds and publishes the GitHub Release.
- The stable release includes server `release` assets for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, and router `release-router` assets for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.
- Router archives are named `outline-ws-rust-router-v<version>-<target>.tar.gz` so they are distinct from the regular server assets.
- Pushing a tag like `v1.2.3` manually still triggers the `Tag Release` workflow as a separate external tag-driven path.

Install the required Rust targets:

```bash
# VMs / servers
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl

# Routers (ARM, e.g. Raspberry Pi, many modern home routers)
rustup target add armv7-unknown-linux-musleabihf
# Routers (AArch64, e.g. newer Raspberry Pi, Banana Pi, routers with Cortex-A53+)
rustup target add aarch64-unknown-linux-musl
```

Current stable Rust no longer ships `mips-unknown-linux-musl` or `mipsel-unknown-linux-musl` as downloadable `rust-std` targets, so local shortcuts only cover the targets still available on stable. Legacy MIPS builds now require a pinned older toolchain or a custom `build-std` flow; official stable release assets for those targets are produced in the `Release` CI workflow.

---

### Feature flags

The binary is controlled by Cargo feature flags. Mix and match as needed:

| Feature | Default | Effect |
|---|---|---|
| `h3` | ✓ | H3/QUIC transport (pulls in quinn + sockudo-ws/http3) |
| `metrics` | ✓ | Prometheus metrics endpoint; also enables transport-layer metrics (pulls in prometheus + serde_json) |
| `tun` | ✓ | TUN device support (tun2udp + tun2tcp engines); remove to exclude all TUN code |
| `mimalloc` | ✓ | Replace the system allocator with mimalloc; reduces RSS fragmentation under connection churn |
| `env-filter` | ✓ | Dynamic `RUST_LOG` parsing; disable to hardcode log level at `WARN` and save ~300 KB on MIPS |
| `multi-thread` | ✓ | Tokio work-stealing scheduler; disable to force `current_thread` and save ~100–200 KB |
| `router` | — | Convenience alias for `--no-default-features --features router` (disables all defaults above) |

> **Why disable for routers:** `h3`/QUIC adds ~1–2 MB of binary size and runtime overhead on MIPS/ARM. `metrics` adds prometheus + serde_json and a background sampling task. The `router` feature removes both at once.

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

---

### Routers (cross-compilation)

All router builds use `musl` libc for a fully static binary with no runtime dependencies.
Use `config-router.toml` on the device — see [Router Configuration](#router-configuration).

All router builds use `--no-default-features --features router` which disables:
- `h3` → removes quinn, h3, h3-quinn, sockudo-ws/http3 (~1–2 MB smaller on MIPS)
- `metrics` → removes prometheus, serde_json, background process sampler

Router builds use the `release-router` cargo profile (`opt-level = "z"`) which prioritises binary size over throughput. The default `release` profile uses `opt-level = 3` (maximum speed) and is the right choice for VMs.

**ARM soft-float** (minimal ARM routers without FPU, e.g. older D-Link DIR, Linksys WRT):

```bash
cargo zigbuild --profile release-router --no-default-features --features router --target arm-unknown-linux-musleabi
# or shorter
cargo release-router-musl-arm
```

**ARMv7 hard-float** (Raspberry Pi 2/3 in 32-bit mode, many mid-range routers):

```bash
cargo zigbuild --profile release-router --no-default-features --features router --target armv7-unknown-linux-musleabihf
# or shorter
cargo release-router-musl-armv7
```

**AArch64 / ARM64** (Raspberry Pi 3/4/5 in 64-bit mode, Banana Pi R3/R4, NanoPi R5S, routers with MT7986/MT7988, IPQ8074):

```bash
cargo zigbuild --profile release-router --no-default-features --features router --target aarch64-unknown-linux-musl
# or shorter
cargo release-router-musl-aarch64
```

The compiled binary is placed in `target/<target>/release-router/outline-ws-rust`.
Copy it to the router and make it executable:

```bash
scp target/armv7-unknown-linux-musleabihf/release-router/outline-ws-rust root@192.168.1.1:/usr/local/bin/
ssh root@192.168.1.1 chmod +x /usr/local/bin/outline-ws-rust
```

> The `router` feature is a convenience alias — it sets no flags itself; it just exists so `--features router` is a memorable shorthand for `--no-default-features`.

### Router Release Assets

Stable Rust no longer provides prebuilt `rust-std` for `mips-unknown-linux-musl` / `mipsel-unknown-linux-musl`, so these builds now need nightly plus `build-std`. For local builds you still need a working MIPS musl-capable C toolchain (or equivalent Zig wrapper setup); the easiest reliable path for official stable artifacts is the `Release` CI flow.

Local example, assuming you already have a working MIPS musl C toolchain:

```bash
rustup toolchain install nightly --component rust-src
cargo +nightly build -Z build-std=std,panic_abort --profile release-router --no-default-features --features router --target mipsel-unknown-linux-musl
```

CI / release example:

- Run the manual `Release` workflow for the normal stable release, or push a tag like `v1.2.3` for the external tag-driven path.
- The `Release` workflow publishes one GitHub Release for both server and router assets.
- For `aarch64-unknown-linux-musl`, router binaries are built with `cargo-zigbuild`.
- For `mips` and `mipsel`, CI uses nightly `build-std`, Zig, and generated compiler wrapper scripts mapped to Zig's musl EABI targets instead of downloading an external toolchain archive.
- The published router assets are named `outline-ws-rust-router-v<version>-<target>.tar.gz`.

---

### Router Configuration

Use `config-router.toml` as a starting point for memory-constrained devices.
Key differences from the default VM config:

**Compile-time (feature flags):**

| Feature | VM default | Router (`--no-default-features --features router`) |
|---|---|---|
| `h3` | ✓ enabled | ✗ → H3 silently falls back to H2 |
| `metrics` | ✓ enabled | ✗ → all metrics calls are no-ops, no `/metrics` endpoint |
| `env-filter` | ✓ enabled | ✗ → log level hardcoded to `WARN` (saves ~300 KB, no regex) |
| `multi-thread` | ✓ enabled | ✗ → always `current_thread` scheduler (saves ~100–200 KB) |

**Runtime (config / CLI):**

| Parameter | VM default | Router example |
|---|---|---|
| `RUST_LOG` env | configurable (default: `info,outline_ws_rust=debug`) | hardcoded `WARN` (no regex) |
| `--worker-threads` | CPU count | N/A (always `current_thread`) |
| `--thread-stack-size-kb` | 2048 KiB | N/A (`multi-thread` disabled) |
| `udp_recv_buf_bytes` | kernel default | e.g. `212992` (208 KiB) |
| `udp_send_buf_bytes` | kernel default | e.g. `212992` (208 KiB) |
| `tun.max_flows` | 4096 | 128 |
| `tun.defrag_max_fragment_sets` | 1024 | 64 |
| `tun.defrag_max_fragments_per_set` | 64 | 16 |
| `tun.defrag_max_total_bytes` | 16 MiB | 2 MiB |
| `tun.defrag_max_bytes_per_set` | 128 KiB | 16 KiB |
| `tun.tcp.max_pending_server_bytes` | 4 MiB | 64 KiB |
| `tun.tcp.max_buffered_client_bytes` | 256 KiB | 64 KiB |
| `[h2] initial_stream_window_size` | 1 MiB | 256 KiB |
| `[h2] initial_connection_window_size` | 2 MiB | 512 KiB |
| Warm standby | 1 TCP + 1 UDP | disabled |
| Load balancing mode | `active_active` | `active_passive` |
| Transport mode | `h3` | `h2` (QUIC is heavy on MIPS/ARM) |
| `state_path` | config dir (`.state.toml`) | point to writable path, e.g. `/var/lib/outline-ws-rust/state.toml` |

Run with the router config:

```bash
outline-ws-rust --config /etc/outline-ws-rust/config-router.toml --worker-threads 1
```

Or via environment variables:

```bash
PROXY_CONFIG=/etc/outline-ws-rust/config-router.toml WORKER_THREADS=1 outline-ws-rust
```

> Router builds log at `WARN` level unconditionally — `RUST_LOG` is ignored. To get dynamic log levels, add `--features env-filter` to the build command (at the cost of ~300 KB on MIPS).

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
# max_flows = 4096
# idle_timeout_secs = 300

# [tun.tcp]
# connect_timeout_secs = 10
# handshake_timeout_secs = 15
# half_close_timeout_secs = 60
# max_pending_server_bytes = 4194304
# backlog_abort_grace_secs = 3
# backlog_hard_limit_multiplier = 2
# backlog_no_progress_abort_secs = 8
# max_buffered_client_segments = 4096
# max_buffered_client_bytes = 262144
# max_retransmits = 12

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
url = "http://example.com/"

# `outline.probe.http` sends an HTTP `HEAD` request (not `GET`), so health
# checks do not download response bodies through the uplink.

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
transport = "websocket"
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
transport = "websocket"
tcp_ws_url = "wss://backup.example.com/SECRET/tcp"
weight = 0.8
tcp_mode = "h2"
udp_ws_url = "wss://backup.example.com/SECRET/udp"
udp_mode = "h2"
method = "chacha20-ietf-poly1305"
password = "Secret0"

# VLESS-over-WebSocket uplink. Shares the WSS dial path with the "websocket"
# transport; `vless_id` replaces the Shadowsocks cipher/password. The VLESS
# server exposes one WS path (`ws_path_vless`) shared by TCP and UDP, so the
# client takes a single `vless_ws_url`/`vless_ws_mode` pair — using
# `tcp_ws_url`/`udp_ws_url` with `transport = "vless"` is rejected at parse
# time.
[[outline.uplinks]]
name = "vless-edge"
group = "main"
transport = "vless"
vless_ws_url = "wss://vless.example.com/SECRET/vless"
vless_ws_mode = "h2"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 0.5

# VLESS over raw QUIC (ALPN = "vless"). Set vless_ws_mode = "quic" to
# bypass the WebSocket layer entirely and ride VLESS framing directly on
# QUIC bidi streams (TCP) and datagrams (UDP, prefixed with the
# server-allocated 4-byte session_id). Only host:port from the URL is
# used. On dial / handshake failure raw-QUIC paths fall back to WS over
# H2 (then H1) and open the H3-downgrade window so subsequent dials skip
# QUIC until the recovery probe confirms it again.
[[outline.uplinks]]
name = "vless-quic"
group = "main"
transport = "vless"
vless_ws_url = "https://vless.example.com:443"
vless_ws_mode = "quic"
vless_id = "11111111-2222-3333-4444-555555555555"
weight = 1.0

# Shadowsocks over raw QUIC (ALPN = "ss"). One QUIC bidi per SS-TCP
# session; SS-UDP rides QUIC datagrams 1:1 with SS-AEAD packets. Same
# cipher / password as the WS path. transport = "websocket" + tcp_mode =
# "quic" selects this path; transport = "vless" + tcp_mode = "quic"
# selects the VLESS branch above.
[[outline.uplinks]]
name = "ss-quic"
group = "main"
transport = "websocket"
tcp_ws_url = "https://ss.example.com:443"
udp_ws_url = "https://ss.example.com:443"
tcp_mode = "quic"
udp_mode = "quic"
method = "chacha20-ietf-poly1305"
password = "Secret0"
weight = 1.0

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

- `transport` accepts `websocket` (default), `shadowsocks`, or `vless`. VLESS shares the WSS dial path with `websocket` (same `tcp_ws_url` / `udp_ws_url` / `tcp_mode` / `udp_mode` / `ipv6_first` / `fwmark` fields) but authenticates with a single `vless_id` instead of a Shadowsocks `method` + `password`. VLESS UDP opens one WSS session per destination inside the uplink (bounded by `[outline.load_balancing] vless_udp_max_sessions`, LRU-evicted, with idle eviction controlled by `vless_udp_session_idle_secs`).
- At least one ingress must be configured: `--listen` / `[socks5].listen` and/or `[tun]`. If neither is present, the process exits with an error instead of silently binding `127.0.0.1:1080`.
- `tcp_mode` / `udp_mode` (`transport = "ws"`) and `vless_ws_mode` (`transport = "vless"`) accept `http1` (alias `h1`), `h2`, `h3`, or `quic`. Modes `http1` / `h2` / `h3` ride a WebSocket Upgrade over the matching HTTP version (with automatic `h3 → h2 → http1` fallback for WS modes); `quic` selects raw QUIC framing on ALPN `vless` (for VLESS) or `ss` (for Shadowsocks-over-WS) with `quic → h2 → http1` dial-time fallback.
- `tcp_addr` / `udp_addr` are used with `transport = "shadowsocks"` and accept `host:port` or `[ipv6]:port`.
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
- `h3_downgrade_secs` (per-group, default `60`, also accepted as `mode_downgrade_secs`): how long an uplink that experienced a failure on its advanced mode — H3 application-level error (e.g. `H3_INTERNAL_ERROR`) **or** raw-QUIC dial / handshake failure — stays in H2 fallback mode before the original mode is retried. Applies to both `transport = "ws"` and `transport = "vless"`. Set to `0` to disable automatic downgrade.
- `state_path` (optional): path to a TOML file where the active-uplink selection is persisted across restarts. Defaults to the config file path with the extension replaced by `.state.toml` (e.g. `config.toml` → `config.state.toml`). If the file cannot be written (e.g. config lives in a read-only `/etc/` directory under `ProtectSystem=strict`), the process logs a warning at startup and continues without persistence. The bundled systemd units set `STATE_PATH=/var/lib/outline-ws-rust/state.toml` so the state lands in the writable state directory. Only the active-uplink selection is persisted (by uplink name); EWMA and penalty values are not — they are re-established within one probe cycle after restart.
- Uplink groups (`[[uplink_group]]`) each hold their own probe loop, standby pool, sticky-routes store, active-uplink state, and load-balancing policy — groups are fully isolated at runtime.
- `[outline.probe]` acts as a template: each group inherits it, and `[uplink_group.probe]` overrides individual fields per group. Probe sub-tables (`ws`/`http`/`dns`/`tcp`) are replaced wholesale — if a group sets `[uplink_group.probe.http]`, the template's `[outline.probe.http]` is dropped for that group.
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

Matching is done on resolved IP addresses; domain-name targets never match a rule and fall through to the default.

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

# Explicit default — matches everything not caught above.
[[route]]
default = true
via = "main"
fallback_direct = true    # or: fallback_drop = true / fallback_via = "backup"
```

Rule fields:

- `prefixes` / `file` / `files`: inline list and/or one or more paths to files (one CIDR per line, `#` comments and blank lines ignored). All sources are merged into the rule's CIDR set. `file` is a convenience shorthand for a single-entry `files`; both may be combined.
- `file_poll_secs`: how often (in seconds) to `stat` each file and reload its CIDRs on mtime change. Default `60`. Applies to every path in `files`.
- `via`: target for matching traffic. Required (except on `default = true` rules, where it picks the fallthrough target).
- `fallback_via` / `fallback_direct` / `fallback_drop`: mutually exclusive; consulted when the primary `via` is a group that has zero healthy uplinks at dispatch time.
- `default = true`: exactly one rule must carry this; it matches everything not caught by the previous rules. The `default` rule must not set `prefixes`, `file`, or `files`.

### Prefix matching

Internally each rule's inline + file prefixes are merged into a [`CidrSet`](src/routing/cidr.rs) — sorted `[start, end]` ranges (IPv4 as `u32`, IPv6 as `u128`) with overlapping and adjacent ranges merged. Lookup uses `partition_point` (binary search), O(log n) per rule.

### Hot-reload

Every rule with at least one `file` / `files` entry gets a background tokio task that polls `mtime` of every listed path every `file_poll_secs` seconds. When any of them changes, the rule's CIDR set is rebuilt from its inline prefixes plus all reloaded files and swapped atomically (`Arc<RwLock<CidrSet>>`) — other rules and the table shape are unaffected. Parse or read errors on reload leave the previous CIDR set in place and log a warning.

### Direct session idle timeout

`direct` connections are subject to a 2-minute bidirectional idle timeout. If no bytes flow in either direction for 120 seconds, both sockets are closed and FDs reclaimed. This prevents unbounded FD accumulation from clients that open TCP connections (e.g. DNS-over-HTTPS, DNS-over-TLS) and abandon them without sending FIN — leaving the server half open indefinitely. Any data activity in either direction resets the timer, so legitimate long-lived push-notification and keepalive connections are unaffected.

### Fallback semantics

When the primary `via` resolves to a group with no currently-healthy uplinks, the rule's fallback target is tried instead (one level, no recursion). Health is checked non-side-effectingly at dispatch time via `UplinkManager::has_any_healthy(transport)`; this is cheaper than building a candidate list and does not touch sticky-routes state. If the primary group recovers mid-session, future connections go through it normally — fallback is only consulted at dispatch.

## Transport Modes

### HTTP/1.1

Use when you want the most compatible baseline behavior.

### HTTP/2

Use when the upstream supports RFC 8441 Extended CONNECT for WebSockets.

### HTTP/3

Use when the upstream supports RFC 9220 and QUIC/UDP is available end to end.

### Raw QUIC

Use when the upstream runs the matching raw-QUIC listener (outline-ss-rust `transport::raw_quic`). Selected per uplink via `tcp_mode = "quic"` / `udp_mode = "quic"` (for `transport = "ws"`) or `vless_ws_mode = "quic"` (for `transport = "vless"`). The path skips WebSocket and HTTP/3 framing entirely:

- VLESS-TCP / SS-TCP — one QUIC bidi stream per session.
- VLESS-UDP — per-target control bidi (server returns a 4-byte `session_id`) plus connection-level datagram demux.
- SS-UDP — 1 QUIC datagram = 1 SS-AEAD packet (RFC 9221).
- ALPNs `vless-mtu` / `ss-mtu` — auxiliary stream-fallback for oversized UDP payloads that exceed the QUIC datagram limit.
- Multiple sessions of the same ALPN to the same `host:port` share one cached QUIC connection.
- Only `host:port` from the dial URL is used; the path is ignored.

Recommended operator stance:

- prefer `http1` as a conservative baseline
- enable `h2` only when the reverse proxy and origin are known-good for RFC 8441
- enable `h3` only when QUIC is explicitly supported and reachable
- enable `quic` only when the matching outline-ss-rust raw-QUIC listener is reachable end to end

**Shared QUIC endpoint:** H3 and raw-QUIC connections that do not use a per-uplink `fwmark` share a single UDP socket per address family (one for IPv4, one for IPv6). This means N warm-standby connections do not open N UDP sockets. Connections that require a specific `fwmark` still use their own dedicated socket because the mark must be applied before the first `sendmsg`.

QUIC keep-alive pings are sent every 10 seconds to prevent NAT mapping expiry and to allow the server to detect dead connections without waiting for the full idle timeout.

Runtime fallback behavior:

- requested `h3` tries `h3`, then `h2`, then `http1`
- requested `h2` tries `h2`, then `http1`
- requested `quic` tries raw QUIC, then WS over `h2`, then WS over `http1` on dial / handshake failure

**Mode downgrade window:** when an "advanced mode" failure (H3 application-level error such as `H3_INTERNAL_ERROR`, **or** a raw-QUIC dial / handshake failure) occurs on an uplink that requested H3 or QUIC, the uplink automatically falls back to H2 for new TCP and UDP connections for the duration configured by `h3_downgrade_secs` (default: 60 seconds; also accepted as `mode_downgrade_secs`). After the window expires, the original mode is retried by the next real connection. This prevents reconnect storms where every new flow establishes a QUIC / H3 connection only to have it fail shortly after.

The same downgrade is also triggered by TCP probe failures on H3 / QUIC uplinks, preventing probe-driven flapping in `active_passive + global` mode: without this, intermittent advanced-mode probe pass/fail alternation would cause a failover switch every probe cycle.

Probe behavior during a downgrade window:
- Probes use `effective_tcp_mode` / `effective_udp_mode`, which return H2 while the downgrade timer is active. The probe therefore tests H2 connectivity during the window rather than continuing to stress-test broken H3 / QUIC.
- A successful probe during the window does **not** clear the downgrade timer. Recovery is tested naturally once the timer expires and the next real connection attempts the original mode. If that attempt fails, the timer is reset.

Scoring during a downgrade window (`per_flow` scope):
- While the downgrade timer is active, the uplink's effective latency score has `failure_penalty_max` added on top of the normal failure penalty. This prevents `active_active + per_flow` flows from switching back to the primary uplink while it is operating in H2 fallback mode: as the normal failure penalty decays, the extra downgrade penalty keeps the primary's score unfavorable until the window closes.

Warm-standby connections respect the active downgrade state: while an uplink is in H3→H2 or QUIC→H2 downgrade, new standby slots are filled using H2.

**VLESS-UDP raw-QUIC hybrid mux:** because VLESS-UDP raw-QUIC sessions dial lazily on the first packet, the SS-style "try QUIC at acquire time, fall back if that fails" pattern doesn't apply directly. Instead, the VLESS-UDP path is wrapped in a hybrid mux that owns both a QUIC inner mux and a WS-over-H2 inner mux: it dials QUIC first, and on first-dial failure pivots to WS, calls `note_advanced_mode_dial_failure` to start the cooldown, and proxies downlink datagrams from whichever inner mux is currently active. A latched `quic_succeeded_once` flag prevents collapse to WS once a QUIC session has actually completed — runtime errors on a working QUIC session still propagate as real failures.

**Transport handshake timeouts:** every WebSocket connect path enforces an upper bound so that a silently-broken or black-holed server cannot stall new sessions for minutes while keeping the uplink nominally "healthy".

- **Fresh connect** (new TCP/QUIC + TLS + protocol handshake): 10 s for H1, H2, and H3. Without this bound a network black hole can hang up to ~127 s (Linux TCP SYN retransmit, H1/H2) or up to 120 s (QUIC `max_idle_timeout`, H3).
- **Reused shared H2/H3 connection** (opening a new WebSocket stream over an already-established connection): 7 s per await for H3, 10 s per await for H2. This catches the case where the shared pool handle is still nominally "open" to the client-side library but the underlying path has died — e.g. NAT rebinding, server graceful close received late, or silent packet loss.

When a timeout fires, the error is treated as an upstream runtime failure: the shared pool entry (if any) is invalidated on the next open attempt, `report_runtime_failure` sets a cooldown, and the probe is woken immediately. In `active_passive + global` mode the active uplink is replaced only after the probe confirms the primary as down on a fresh connect of its own — transient shared-pool glitches do not change the exit IP, while recovery when the primary is genuinely unreachable is bounded to roughly one probe cycle.

**Shared connection reconnect serialization:** when the shared H2 or H3 connection drops and N sessions simultaneously try to reconnect, only one new TCP+TLS+H2 or QUIC+TLS+H3 handshake is performed. A per-server-key `tokio::sync::Mutex<()>` serialises the slow path: the first waiter establishes the connection and caches it; all other waiters find the fresh entry under the lock and reuse it without starting their own handshake. This prevents thundering herd storms where N sessions each independently open a full TLS negotiation toward the same server after a shared connection drop.

**SOCKS5 negotiation abort classification:** when a local SOCKS5 client (TUN interceptor such as Sing-box or Clash) aborts the handshake early — closing the TCP connection after the method-negotiation greeting but before or during the CONNECT request — the resulting `early eof` / `failed to read request header` errors are classified as expected client disconnects and logged at `debug` level rather than `warn`. This is normal behaviour during reconnect storms when the TUN interceptor flushes its connection pool.

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

Probe timing:

- Probes normally run on a fixed `interval` timer.
- When a runtime failure sets a fresh failure cooldown on an uplink, the probe loop is immediately woken up (via an internal `Notify`) so that failover is confirmed within one probe cycle rather than waiting for the next scheduled interval. This significantly reduces end-to-end failover latency.
- **Probe suppression under active traffic (global + probe):** in `routing_scope = global` mode with probes enabled, the probe cycle is skipped for an uplink when all three conditions are met: (1) real traffic was observed within the last `interval`, (2) the uplink is probe-healthy (`tcp_healthy = true`), (3) routing scope is `global`. Active traffic is stronger evidence of reachability than a probe ping. This prevents false-negative probe results under load: when the probe loop wakes immediately after an H3 runtime failure, the server may be busy and unable to accept a new QUIC connection for the probe — which would otherwise cause a spurious failover. For non-global scopes the probe still runs even when traffic is active, to confirm recovery after cooldown.

Warm-standby validation:

- Every 15 seconds, standby connections are validated using a 1 ms non-blocking read. If the server closed the connection (EOF, close frame, or error), the slot is cleared and refilled. A timeout (no data in 1 ms) means the connection is still open.

Probe activation rules:

- probes do not start unless probe settings are explicitly configured
- `[probe]` alone does not enable any check
- at least one of `[probe.ws]`, `[probe.http]`, or `[probe.dns]` must be present

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

- `outline_ws_rust_process_resident_memory_bytes`
- `outline_ws_rust_process_virtual_memory_bytes`
- `outline_ws_rust_process_heap_allocated_bytes`
- `outline_ws_rust_process_heap_mode_info{mode}`
- `outline_ws_rust_process_open_fds`
- `outline_ws_rust_process_threads`

Heap metrics currently fall back to `VmData`-based estimation on Linux and export `heap_mode_info{mode="estimated"}`.

On Linux, the process also emits a periodic descriptor inventory log:

- `process fd snapshot`

The descriptor snapshot includes total open FDs plus a breakdown for sockets, pipes, anon inodes, regular files, and other descriptor types.

`outline_ws_rust_selection_mode_info{mode}`, `outline_ws_rust_routing_scope_info{scope}`, `outline_ws_rust_global_active_uplink_info{uplink}`, and `outline_ws_rust_sticky_routes_total` expose selector configuration and active-uplink state.
When TUN UDP forwarding fails before a packet can be delivered upstream, `outline_ws_rust_tun_udp_forward_errors_total{reason}` breaks that down into `all_uplinks_failed`, `transport_error`, `connect_failed`, and `other`.
Oversized SOCKS5 UDP packets dropped before uplink forwarding, and oversized UDP responses dropped before client delivery, are exported as `outline_ws_rust_udp_oversized_dropped_total{direction="incoming|outgoing"}`.
Local ICMP echo handling is exported separately via `outline_ws_rust_tun_icmp_local_replies_total{ip_family}`.

For direct `transport = "shadowsocks"` UDP uplinks, the same oversized checks still apply on the local relay boundaries:

- incoming: the relay drops the packet if `target + payload` exceeds the Shadowsocks AEAD payload limit before encrypting and sending it to the uplink
- outgoing: the relay drops the packet if the decoded upstream response becomes larger than a safe SOCKS5 UDP datagram before sending it back to the client

Grafana dashboards:

- [`grafana/outline-ws-rust-dashboard.json`](grafana/outline-ws-rust-dashboard.json)
- [`grafana/outline-ws-rust-tun-tcp-dashboard.json`](grafana/outline-ws-rust-tun-tcp-dashboard.json)
- [`grafana/outline-ws-rust-native-burst-dashboard.json`](grafana/outline-ws-rust-native-burst-dashboard.json)

The experimental uplinks/control-plane Grafana dashboard is intentionally not packaged; use the built-in `/dashboard` UI for multi-instance uplink activation.

## Production Operations

### `install.sh`

For a basic production install on Linux use the bundled [install.sh](install.sh) script. Run it as `root` on the target host:

```bash
curl -fsSL https://raw.githubusercontent.com/balookrd/outline-ws-rust/main/install.sh -o install.sh
chmod +x install.sh
./install.sh --help
sudo ./install.sh
```

Install modes:

- Default: installs the latest stable release for the current architecture
- `CHANNEL=nightly`: installs the rolling nightly prerelease
- `VERSION=v1.2.3`: pins the install to a specific stable tag

Examples:

```bash
./install.sh --help
sudo ./install.sh
sudo ./install.sh --force
sudo CHANNEL=nightly ./install.sh
sudo VERSION=v1.2.3 ./install.sh
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
- a fixed `outline-ws` system user / group (provisioned by `install.sh`) so state files keep a stable owner across restarts and `StateDirectory=outline-ws-rust/_default` lands on a writable, unit-managed path
- `CAP_NET_ADMIN` for `fwmark`; remove if `fwmark` is not used
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
- `fwmark` works only on Linux and requires `CAP_NET_ADMIN` or root.
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
