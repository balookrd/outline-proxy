# outline-proxy

`outline-proxy` is a Cargo workspace (monorepo) that hosts both halves of an
Outline-compatible proxy system built on Shadowsocks AEAD and VLESS over
WebSocket / XHTTP / HTTP/3 / raw QUIC.

- **[`outline-ss-rust`](bins/outline-ss-rust/)** — the **server** data plane.
  Accepts Shadowsocks AEAD or VLESS traffic over WebSocket (HTTP/1.1, RFC 8441
  H2, RFC 9220 H3), XHTTP, and raw QUIC, and relays it to arbitrary TCP/UDP
  destinations. Multi-user with per-user policy, Prometheus metrics, optional
  built-in TLS and QUIC/H3 listeners.
- **[`outline-ws-rust`](bins/outline-ws-rust/)** — the **client**. Accepts local
  SOCKS5 (and optional TUN) traffic and forwards it through the matching
  transports, with multi-uplink failover, load balancing, health probes, and a
  stripped **router build** for memory-constrained devices (MIPS / armv7).

The client dials the server; both speak the same wire protocol and share a set
of common crates, which is why they live in one repository.

A **reverse-tunnel** mode (topology A) inverts the carrier so the server can run
behind NAT without a public IP: it dials *out* to the public client, which
listens and routes user traffic back through it. See
[docs/REVERSE-TUNNEL.md](docs/REVERSE-TUNNEL.md).

*Русская версия: [README.ru.md](README.ru.md)*

## Supported protocols & transports

Two independent axes: the **payload protocol** (what rides inside) and the
**carrier transport** (how it is delivered). The client and server negotiate a
pair of both per uplink.

| Payload \ Carrier | WebSocket (h1/h2/h3) | XHTTP (h1/h2/h3) | raw QUIC |
|---|:---:|:---:|:---:|
| **Shadowsocks** (AEAD / SS2022) | ✅ | ✅ (forward TCP + UDP) | ✅ |
| **VLESS** | ✅ | ✅ | ✅ |

XHTTP is a `packet-up` / `stream-one` protocol. VLESS rides it for TCP + UDP on
one path; Shadowsocks rides it on the **forward path** (client→server) for both
TCP and UDP. By default TCP and UDP take separate base paths (server
`xhttp_path_tcp` / `xhttp_path_udp`, mirroring the WS `ws_path_tcp` /
`ws_path_udp` split); optionally they share **one combined path** (server
`xhttp_path_ss`, client `ss_xhttp_url` + `ss_mode`). The TCP/UDP split then
rides a hidden discriminator in the session id, so a censor sees one endpoint
instead of two. The same combined option applies to WebSocket (server
`ws_path_ss`, client `ss_ws_url`). Reverse-tunnel-over-XHTTP is a planned
follow-up. Every other cell is supported in both directions.

The client picks a `transport` + `mode` pair on each uplink:

| `transport` | accepted `*_mode` values | dial URL field |
|---|---|---|
| `ss` (alias `shadowsocks`; deprecated `ws` / `websocket`) | `ws_h1` · `ws_h2` · `ws_h3` · `quic` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `tcp_ws_url` / `udp_ws_url` (ws / quic) · `tcp_xhttp_url` / `udp_xhttp_url` (xhttp) |
| `vless` | `ws_h1` · `ws_h2` · `ws_h3` · `quic` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `vless_ws_url` (ws / quic) · `vless_xhttp_url` (xhttp) |

Carrier aliases: `h1` / `http1` → `ws_h1`, `h2` → `ws_h2`, `h3` → `ws_h3`.

**Carriers**

- **WebSocket h1 / h2 / h3** — RFC 6455, RFC 8441 (H2 Extended CONNECT), RFC 9220
  (H3 Extended CONNECT). The baseline path for both payloads.
- **XHTTP** — two sub-modes: `packet-up` (each packet is its own request, works
  on h1 / h2 / h3) and `stream-one` (a single bidi POST, needs multiplexing —
  h2 / h3 only; the server returns 505 on h1). Carries VLESS (TCP + UDP) and
  Shadowsocks (forward-path TCP + UDP).
- **raw QUIC** — no WebSocket / HTTP framing, ALPN `outline-quic`. Carries both
  Shadowsocks and VLESS. TCP-like sessions ride a fresh bidi stream; UDP-like
  sessions use QUIC datagrams (RFC 9221). Requires the `quic` build feature.

**Automatic fallback** (per uplink, including mid-session): WebSocket descends
`h3 → h2 → h1`, XHTTP descends `xhttp_h3 → xhttp_h2 → xhttp_h1`, and raw QUIC
falls back to WebSocket-over-H2 on a dial failure.

> **Outline compatibility:** Shadowsocks-over-WebSocket is the path the Outline
> apps speak — the server emits an Outline access key (`$type: websocket`,
> TCP + UDP) for it. Shadowsocks-over-QUIC is a standalone mode for the bundled
> `outline-ws-rust` client only and is not exposed as an Outline key. VLESS is
> exposed as a `vless://…` share link (`ws` / `xhttp` / `quic`).

## Layout

```
outline-proxy/
├── bins/
│   ├── outline-ss-rust/   # server binary  (+ its README, CHANGELOG, docs/)
│   └── outline-ws-rust/   # client binary  (+ its README, CHANGELOG, docs/)
├── crates/                # shared crates (wire protocol, transport, uplink, tun, crypto, routing, …)
├── vendor/                # patched h3 + sockudo-ws (single copy, workspace-level)
├── .cargo/config.toml     # cross-build aliases (ss-* / ws-*)
├── .github/workflows/     # CI: per-binary release / nightly / tag pipelines
├── AGENTS.md              # contributor guidelines + monorepo invariants
└── Cargo.toml             # workspace root: members, profiles, [patch.crates-io]
```

Per-binary documentation lives next to each binary —
[server README](bins/outline-ss-rust/README.md) ·
[client README](bins/outline-ws-rust/README.md) — with deeper material under each
`bins/*/docs/` (architecture, session resumption, uplink configuration, TUN PMTUD).

## Build

Both binaries are Rust edition 2024.

```bash
# whole workspace
cargo build --release
cargo test --workspace

# a single binary
cargo build --release -p outline-ss-rust
cargo build --release -p outline-ws-rust

# client router build (stripped, memory-constrained)
cargo build --profile release-router --no-default-features --features router -p outline-ws-rust

# musl cross-builds via cargo-zigbuild aliases (need cargo-zigbuild + zig)
cargo ss-release-musl-x86_64
cargo ws-release-router-musl-armv7
```

`rustls` is pinned to the `ring` provider across the workspace, and the HTTP/3
WebSocket path depends on the patched `vendor/h3` and `vendor/sockudo-ws`. See
[`AGENTS.md`](AGENTS.md) for the full set of monorepo invariants.

## Releases

Each binary versions and releases independently via prefixed tags:

- `ss-v<x.y.z>` → builds and publishes the **server** (workflow *Tag Release (server)*)
- `ws-v<x.y.z>` → builds and publishes the **client** (workflow *Tag Release (client)*)

Pushes to `main` publish rolling `ss-nightly` / `ws-nightly` prereleases
(path-filtered, so only the affected binary rebuilds). The manual
*Release (server|client)* workflows bump the corresponding `bins/*/Cargo.toml`
version and open the tagging flow.

## License

GPL-3.0 — see [LICENSE](LICENSE).
