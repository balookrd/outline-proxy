<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img src="docs/logo-light.png" alt="outline-proxy logo" width="100%">
  </picture>
</p>

# outline-proxy

`outline-proxy` is a Cargo workspace (monorepo) that hosts an
Outline-compatible proxy system built on Shadowsocks AEAD and VLESS over
WebSocket / XHTTP / HTTP/3 — server, client, an aggregating dashboard UI, and
an Android VPN client.

- **[`outline-ss-rust`](bins/outline-ss-rust/)** — the **server** data plane.
  Accepts Shadowsocks AEAD or VLESS traffic over WebSocket (HTTP/1.1, RFC 8441
  H2, RFC 9220 H3) and XHTTP, and relays it to arbitrary TCP/UDP
  destinations. Multi-user with per-user policy, Prometheus metrics, optional
  built-in TLS and QUIC/H3 listeners, and an optional mesh cluster across nodes.
- **[`outline-ws-rust`](bins/outline-ws-rust/)** — the **client**. Accepts local
  SOCKS5 (and optional TUN) traffic and forwards it through the matching
  transports, with multi-uplink failover, load balancing, and health probes.
- **[`outline-ui`](bins/outline-ui/)** — an aggregating **web UI** that serves
  both the server and client dashboards from one binary (`/ss` and `/ws`) with
  no data plane of its own; it only fans out to each node's control API.
- **[`android/`](android/)** — an **Android** VPN client that reuses the whole
  `outline-ws-rust` uplink stack unchanged behind a thin `VpnService` + Compose
  UI layer.

The client dials the server; both speak the same wire protocol and share a set
of common crates, which is why they live in one repository.

*Русская версия: [README.ru.md](README.ru.md)*

## Supported protocols & transports

Two independent axes: the **payload protocol** (what rides inside) and the
**carrier transport** (how it is delivered). The client and server negotiate a
pair of both per uplink.

| Payload \ Carrier | WebSocket (h1/h2/h3) | XHTTP (h1/h2/h3) |
|---|:---:|:---:|
| **Shadowsocks** (AEAD / SS2022) | ✅ | ✅ |
| **VLESS** | ✅ | ✅ |

XHTTP is a `packet-up` / `stream-one` protocol. VLESS rides it for TCP + UDP on
one path; Shadowsocks rides it on the **forward path** (client→server) for both
TCP and UDP. By default TCP and UDP take separate base paths (server
`xhttp_path_tcp` / `xhttp_path_udp`, mirroring the WS `ws_path_tcp` /
`ws_path_udp` split); optionally they share **one combined path** (server
`xhttp_path_ss`, client `ss_xhttp_url` + `ss_mode`). The TCP/UDP split then
rides a hidden discriminator in the session id, so a censor sees one endpoint
instead of two. The same combined option applies to WebSocket (server
`ws_path_ss`, client `ss_ws_url`). Every other cell is supported in both
directions.

The client picks a `transport` + `mode` pair on each uplink:

| `transport` | style | accepted `*_mode` values | dial URL field |
|---|---|---|---|
| `ss` (alias `shadowsocks`; deprecated `ws` / `websocket`) | split | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `tcp_ws_url` / `udp_ws_url` (ws) · `tcp_xhttp_url` / `udp_xhttp_url` (xhttp) |
| `ss` | combined | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `ss_ws_url` or `ss_xhttp_url` + `ss_mode` |
| `vless` | — | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `vless_ws_url` (ws) · `vless_xhttp_url` (xhttp) |

Carrier aliases: `h1` / `http1` → `ws_h1`, `h2` → `ws_h2`, `h3` → `ws_h3`.

**Carriers**

- **WebSocket h1 / h2 / h3** — RFC 6455, RFC 8441 (H2 Extended CONNECT), RFC 9220
  (H3 Extended CONNECT). The baseline path for both payloads.
- **XHTTP** — two sub-modes: `packet-up` (each packet is its own request, works
  on h1 / h2 / h3) and `stream-one` (a single bidi POST, needs multiplexing —
  h2 / h3 only; the server returns 505 on h1). Carries VLESS (TCP + UDP) and
  Shadowsocks (forward-path TCP + UDP).

**Automatic fallback** (per uplink, including mid-session): WebSocket descends
`h3 → h2 → h1` and XHTTP descends `xhttp_h3 → xhttp_h2 → xhttp_h1`.

> **Outline compatibility:** Shadowsocks-over-WebSocket is the path the Outline
> apps speak — the server emits an Outline access key (`$type: websocket`,
> TCP + UDP) for it. Shadowsocks-over-XHTTP is a
> standalone mode for the bundled `outline-ws-rust` client only and is not
> exposed as an Outline key — but a combined-path Shadowsocks user also gets an
> `ss://…` share link (`ws` / `xhttp`, SIP002 userinfo) for that client. VLESS
> is exposed as a `vless://…` share link (`ws` / `xhttp`).

## Layout

```
outline-proxy/
├── bins/
│   ├── outline-ss-rust/   # server binary  (+ its README, CHANGELOG, docs/)
│   ├── outline-ws-rust/   # client binary  (+ its README, CHANGELOG, docs/)
│   └── outline-ui/        # aggregating dashboard UI (+ its README)
├── android/               # Android VPN client (separate workspace: Rust core + Gradle/Kotlin app)
├── crates/                # shared crates (wire protocol, transport, uplink, tun, crypto, routing, …)
├── vendor/                # patched h3 + sockudo-ws (single copy, workspace-level)
├── .cargo/config.toml     # cross-build aliases (ss-* / ws-* / ui-*)
├── .github/workflows/     # CI: per-binary release / nightly / tag pipelines
├── AGENTS.md              # contributor guidelines + monorepo invariants
└── Cargo.toml             # workspace root: members, profiles, [patch.crates-io]
```

Per-binary documentation lives next to each component —
[server README](bins/outline-ss-rust/README.md) ·
[client README](bins/outline-ws-rust/README.md) ·
[dashboard UI README](bins/outline-ui/README.md) ·
[Android client README](android/README.md) — with deeper material under each
`bins/*/docs/` (architecture, session resumption, uplink configuration, TUN PMTUD).

Cross-cutting topics under [`docs/`](docs/):
[carrier padding](docs/PADDING.md) ·
[SS-UDP record framing over XHTTP](docs/XHTTP-UDP-RECORDS.md) ·
[outbound IPv6 source selection](docs/OUTBOUND-IPV6.md) ·
[server mesh cluster](docs/CLUSTER.md) ·
[cluster deployment](docs/CLUSTER-DEPLOY.md).

## Build

Both binaries are Rust edition 2024.

```bash
# whole workspace
cargo build --release
cargo test --workspace

# a single binary
cargo build --release -p outline-ss-rust
cargo build --release -p outline-ws-rust

# musl cross-builds via cargo-zigbuild aliases (need cargo-zigbuild + zig)
cargo ss-release-musl-x86_64
cargo ws-release-musl-aarch64
cargo ui-release-musl-aarch64
```

`rustls` uses the `aws-lc-rs` provider across the workspace, and the HTTP/3
WebSocket path depends on the patched `vendor/h3` and `vendor/sockudo-ws`. See
[`AGENTS.md`](AGENTS.md) for the full set of monorepo invariants.

The Android client lives under [`android/`](android/) as a **separate** Cargo
workspace (the root `cargo build --workspace` does not reach it) plus a
Gradle/Kotlin app; build it from there — see [its README](android/README.md).

## Releases

Each binary versions and releases independently via prefixed tags:

- `ss-v<x.y.z>` → builds and publishes the **server** (workflow *Tag Release (server)*)
- `ws-v<x.y.z>` → builds and publishes the **client** (workflow *Tag Release (client)*)
- `ui-v<x.y.z>` → builds and publishes the **dashboard UI** (workflow *Tag Release (ui)*)
- `android-v<x.y.z>` → builds and publishes the **Android app** (workflow *Tag Release (android)*)

Pushes to `main` publish rolling `ss-nightly` / `ws-nightly` / `ui-nightly` /
`android-nightly` prereleases (path-filtered, so only the affected component
rebuilds — the Android filter also covers the client and the shared crates its
native library links). The manual *Release (server|client|ui)* workflows bump the
corresponding `bins/*/Cargo.toml` version and open the tagging flow.

### Installing the Android app

The app is not on any store: each release attaches a **signed APK**
(`outline-proxy-<version>-arm64-v8a.apk`, or
`outline-proxy-nightly-<sha>-arm64-v8a.apk` on the rolling tag) to its GitHub
release — download it and open it to install. An installed build can also fetch
its own updates: tapping the version label at the bottom of the home screen
checks whatever channel that build came from, downloads the APK into Downloads,
and hands it to the system installer. It never installs anything itself, which
is why the app asks for no install permission.

## License

GPL-3.0 — see [LICENSE](LICENSE).
