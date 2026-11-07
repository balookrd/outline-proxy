<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img src="docs/logo-light.png" alt="outline-proxy logo" width="100%">
  </picture>
</p>

# outline-proxy

`outline-proxy` is a Cargo workspace (monorepo) with an Outline-compatible proxy
built on Shadowsocks AEAD and VLESS over WebSocket / XHTTP / HTTP/3. It contains
the server, the client, an aggregating dashboard UI, an Android VPN client and a
macOS menu-bar client.

- [`outline-ss-rust`](bins/outline-ss-rust/) is the server data plane. It
  accepts Shadowsocks AEAD or VLESS traffic over WebSocket (HTTP/1.1, RFC 8441
  H2, RFC 9220 H3) and XHTTP and relays it to arbitrary TCP/UDP destinations.
  Users carry their own `method`, `fwmark`, `enabled` flag and IP `aliases`; the
  server exports Prometheus metrics and can run built-in TLS and QUIC/H3
  listeners and a mesh cluster across nodes.
- [`outline-ws-rust`](bins/outline-ws-rust/) is the client. It accepts local
  SOCKS5 (and, optionally, TUN) traffic and forwards it over the same carriers,
  with multi-uplink failover, load balancing and health probes.
- [`outline-ui`](bins/outline-ui/) serves both the server and the client
  dashboards from one binary (`/ss` and `/ws`). It has no data plane and only
  queries each node's control API.
- [`android/`](android/) is an Android VPN client. It runs the
  `outline-ws-rust` uplink stack unchanged under a `VpnService` + Compose UI
  layer.
- [`macos/`](macos/) is a macOS menu-bar client. It switches between the SOCKS5
  system proxy mode (no root) and the TUN mode (L3 VPN over the kernel `utun`
  interface), manages server profiles and shows live logs; it does not need a
  paid Apple Developer account. `./macos/scripts/package-dmg.sh` and GitHub
  Actions build a Universal DMG.

The client dials the server; both speak the same wire protocol and share a set
of common crates, which is why they live in one repository.

*Русская версия: [README.ru.md](README.ru.md)*

## Supported protocols and transports

There are two independent axes: the payload protocol (what rides inside) and
the carrier (how it is delivered). The client and the server agree on one pair
per uplink.

| Payload \ Carrier | WebSocket (h1/h2/h3) | XHTTP (h1/h2/h3) |
|---|:---:|:---:|
| Shadowsocks (AEAD / SS2022) | yes | yes |
| VLESS | yes | yes |

XHTTP is a `packet-up` / `stream-one` protocol. VLESS rides it for TCP + UDP on
one path; Shadowsocks rides it on the forward path (client→server) for both TCP
and UDP. By default TCP and UDP use separate server endpoints
(`[[endpoint]] kind = "xhttp_ss_tcp"` / `"xhttp_ss_udp"`, the same split as
`ws_ss_tcp` / `ws_ss_udp` for WebSocket). Optionally they share one combined
endpoint (server `kind = "xhttp_ss"`, client `ss_xhttp_url` + `ss_mode`); the
TCP/UDP split then rides a hidden discriminator in the session id, so a censor
sees one endpoint instead of two. WebSocket has the same combined option
(server `kind = "ws_ss"`, client `ss_ws_url`). Every other cell is supported in
both directions.

The client picks a `transport` + `mode` pair on each uplink:

| `transport` | style | accepted `*_mode` values | dial URL field |
|---|---|---|---|
| `ss` (alias `shadowsocks`; deprecated `ws` / `websocket`) | split | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `tcp_ws_url` / `udp_ws_url` (ws) · `tcp_xhttp_url` / `udp_xhttp_url` (xhttp) |
| `ss` | combined | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `ss_ws_url` or `ss_xhttp_url` + `ss_mode` |
| `vless` | — | `ws_h1` · `ws_h2` · `ws_h3` · `xhttp_h1` · `xhttp_h2` · `xhttp_h3` | `vless_ws_url` (ws) · `vless_xhttp_url` (xhttp) |

Mode aliases: `h1` / `http1` → `ws_h1`, `h2` → `ws_h2`, `h3` → `ws_h3`.

### Carriers

- WebSocket h1 / h2 / h3: RFC 6455, RFC 8441 (H2 Extended CONNECT), RFC 9220
  (H3 Extended CONNECT). Carries both payloads.
- XHTTP has two sub-modes: `packet-up` (each packet is its own request, works on
  h1 / h2 / h3) and `stream-one` (a single bidirectional POST; it needs
  multiplexing, so h2 / h3 only, and the server answers 505 on h1). It carries
  VLESS (TCP + UDP) and Shadowsocks (forward-path TCP + UDP).

Automatic fallback works per uplink, including mid-session: WebSocket descends
`h3 → h2 → h1`, XHTTP descends `xhttp_h3 → xhttp_h2 → xhttp_h1`.

### Outline compatibility

Shadowsocks over WebSocket is the path the Outline apps speak. The access-key
generator [`ops/access-keys`](ops/access-keys/) emits an Outline access key
(`$type: websocket`, TCP + UDP) for a user when the server has a split
`ws_ss_tcp` / `ws_ss_udp` endpoint pair. Shadowsocks over XHTTP works only with
the bundled `outline-ws-rust` client and has no Outline key; for each combined
endpoint (`ws_ss` / `xhttp_ss`) the generator emits an `ss://…` share link
(SIP002 userinfo) for that client instead. VLESS endpoints (`ws_vless` /
`xhttp_vless`) get a `vless://…` share link.

## Layout

```
outline-proxy/
├── bins/
│   ├── outline-ss-rust/   # server binary  (+ its README, CHANGELOG, docs/)
│   ├── outline-ws-rust/   # client binary  (+ its README, CHANGELOG, docs/)
│   └── outline-ui/        # aggregating dashboard UI (+ its README)
├── android/               # Android VPN client (separate workspace: Rust core + Gradle/Kotlin app)
├── macos/                 # macOS menu-bar client (Swift/AppKit)
├── crates/                # shared crates (wire protocol, transport, uplink, tun, crypto, routing, …)
├── vendor/                # patched h3, sockudo-ws, quinn-proto, rustls, hyper (single copy, workspace-level)
├── .cargo/config.toml     # cross-build aliases (ss-* / ws-* / ui-*)
├── .github/workflows/     # CI: lint/test gate, per-component release / nightly / tag pipelines
├── AGENTS.md              # contributor guidelines + monorepo invariants
├── PATCHES.md             # what each vendored crate changes against upstream
└── Cargo.toml             # workspace root: members, profiles, [patch.crates-io]
```

Per-component documentation lives next to each component:
[server README](bins/outline-ss-rust/README.md) ·
[client README](bins/outline-ws-rust/README.md) ·
[dashboard UI README](bins/outline-ui/README.md) ·
[Android client README](android/README.md) ·
[macOS client README](macos/README.md). More detail is under each
`bins/*/docs/`: server architecture and session resumption, client uplink
configurations, TUN PMTUD and TUN GSO.

Cross-cutting topics under [`docs/`](docs/):
[carrier padding](docs/PADDING.md) ·
[SS-UDP record framing over XHTTP](docs/XHTTP-UDP-RECORDS.md) ·
[outbound IPv6 source selection](docs/OUTBOUND-IPV6.md) ·
[server mesh cluster](docs/CLUSTER.md) ·
[cluster deployment](docs/CLUSTER-DEPLOY.md).

[`scripts/code-index.py`](scripts/code-index.py) generates a local structural
map of the workspace (packages, files, top-level items); usage is in
[`docs/CODE-INDEX.md`](docs/CODE-INDEX.md).

## Build

Both binaries are Rust edition 2024.

```bash
# whole workspace
cargo build --release
cargo test --workspace --exclude sockudo-ws

# a single binary
cargo build --release -p outline-ss-rust
cargo build --release -p outline-ws-rust

# musl cross-builds via cargo-zigbuild aliases (need cargo-zigbuild + zig)
cargo ss-release-musl-x86_64
cargo ws-release-musl-aarch64
cargo ui-release-musl-aarch64
```

`sockudo-ws` is an explicit workspace member, so a bare `--workspace` includes
it; CI excludes it, and so does the test command above.

`rustls` uses the `aws-lc-rs` provider across the workspace. The HTTP/3
WebSocket path depends on the patched `vendor/h3` and `vendor/sockudo-ws`; the
patches to all five vendored crates are described in [`PATCHES.md`](PATCHES.md).
See [`AGENTS.md`](AGENTS.md) for the monorepo invariants and the exact CI gate
commands.

The Android client lives under [`android/`](android/) as a separate Cargo
workspace (the root `cargo build --workspace` does not reach it) plus a
Gradle/Kotlin app; build it from there, see [its README](android/README.md).

## Releases

Each component is versioned and released independently through prefixed tags:

| Tag | Builds and publishes | Workflow |
|---|---|---|
| `ss-v<x.y.z>` | server | *Tag Release (server)* |
| `ws-v<x.y.z>` | client | *Tag Release (client)* |
| `ui-v<x.y.z>` | dashboard UI | *Tag Release (ui)* |
| `android-v<x.y.z>` | Android app | *Tag Release (android)* |
| `macos-v<x.y.z>` | macOS app | *Tag Release (macos)* |

Pushes to `main` publish rolling `ss-nightly` / `ws-nightly` / `ui-nightly` /
`android-nightly` / `macos-nightly` prereleases. Each nightly workflow has a
path filter, so only the affected component rebuilds; the Android and macOS
filters also cover the client and the shared crates and vendored crates their
native code links.

The manual *Release (server|client|ui|android|macos)* workflows take a
`MAJOR.MINOR` series, compute the next patch version from the existing tags,
write it into the component's version file (`bins/*/Cargo.toml` for the three
binaries, `android/rust/Cargo.toml` for Android, `macos/Resources/Info.plist`
for macOS), push a `release: cut <tag>` commit to `main` and print the
`git tag -s <tag>` command to run locally. Pushing that signed tag starts the
matching *Tag Release* workflow.

### Installing the Android app

The app is not in any store. Each release attaches a signed APK
(`outline-proxy-<version>-arm64-v8a.apk`, or
`outline-proxy-nightly-<sha>-arm64-v8a.apk` on the rolling tag) to its GitHub
release; download it and open it to install. An installed build can also fetch
its own updates: tapping the version label at the bottom of the home screen
checks the channel that build came from, downloads the APK into Downloads and
hands it to the system installer. The app never installs anything itself, so it
does not request the install permission.

## License

GPL-3.0, see [LICENSE](LICENSE).
