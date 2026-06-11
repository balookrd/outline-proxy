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

*Русская версия: [README.ru.md](README.ru.md)*

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
