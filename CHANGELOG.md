# Changelog

`outline-proxy` is a single Cargo workspace that merged two formerly separate
projects — the **`outline-ss-rust`** server and the **`outline-ws-rust`**
client. The two binaries version and release **independently**, each under its
own git tags: `ss-v*` / `ws-v*` since the merge (e.g. `ss-v1.5.1`, `ws-v1.5.1`),
and the shared `v1.0.0` … `v1.4.4` tags from before the split. There is no
single workspace version; the detailed, version-by-version history lives in the
per-binary changelogs:

| Component | Changelog | Русский |
|-----------|-----------|---------|
| **Server** (`outline-ss-rust`) | [`bins/outline-ss-rust/CHANGELOG.md`](bins/outline-ss-rust/CHANGELOG.md) | [`CHANGELOG.ru.md`](bins/outline-ss-rust/CHANGELOG.ru.md) |
| **Client** (`outline-ws-rust`) | [`bins/outline-ws-rust/CHANGELOG.md`](bins/outline-ws-rust/CHANGELOG.md) | [`CHANGELOG.ru.md`](bins/outline-ws-rust/CHANGELOG.ru.md) |

Both binaries are at **1.7.0**, released 2026-07-06 (tags `ss-v1.7.0` /
`ws-v1.7.0`); work landed since then sits in each binary's `## Unreleased`
section. Adaptive carrier
padding, TUN GSO / GRO / USO offload, and connection sniffing with destination
override all shipped earlier in this line. The headline recent work spans the
whole system:

- **Server mesh cluster.** Edge nodes relay a client's session to the home node
  that owns it, with per-outcome relay metrics and full session migration across
  an edge switch — single-target UDP, VLESS-mux bundles included.
- **Share-link everything.** Combined-path Shadowsocks users get an `ss://…`
  share link alongside the `vless://…` artifacts, and the client can describe a
  whole uplink — or a single fallback wire — from one share-link URI.
- **Deterministic synchronized re-selection** (`load_balancing.reselect_sync`)
  so a cloned node pair rotates onto the same uplink and leaves from one egress.
- **An Android VPN client** ([`android/`](android/)) reusing the `outline-ws-rust`
  uplink stack unchanged, plus the **`outline-ui`** aggregating dashboard service.

See each binary's changelog for the full, version-by-version detail.

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*
