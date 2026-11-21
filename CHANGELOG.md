# Changelog

`outline-proxy` is a single Cargo workspace that merged two formerly separate
projects — the server (formerly **`outline-ss-rust`**, now **`outline-server`**)
and the client (formerly **`outline-ws-rust`**, now **`outline-client`**) —
and grew to cover the dashboard UI, Android, macOS, and Windows clients.
Historical releases used shared `v1.0.0` … `v1.4.4` tags before the split and
per-component `ss-v*` / `ws-v*` / `ui-v*` / `android-v*` / `macos-v*` tags
through `1.9.x`. Starting with `v26.11.0`, the entire repository releases
together under a unified CalVer tag (`vYY.M.PATCH`). Detailed per-component
history for the earlier `1.x` series lives in:

| Component | Changelog | Русский |
|-----------|-----------|---------|
| **Server** (`outline-server`) | [`bins/outline-server/CHANGELOG.md`](bins/outline-server/CHANGELOG.md) | [`CHANGELOG.ru.md`](bins/outline-server/CHANGELOG.ru.md) |
| **Client** (`outline-client`) | [`bins/outline-client/CHANGELOG.md`](bins/outline-client/CHANGELOG.md) | [`CHANGELOG.ru.md`](bins/outline-client/CHANGELOG.ru.md) |
| **Windows client** (`outline-windows`) | [`bins/outline-windows/CHANGELOG.md`](bins/outline-windows/CHANGELOG.md) | [`CHANGELOG.ru.md`](bins/outline-windows/CHANGELOG.ru.md) |
| **Dashboard** (`outline-ui`) | [`bins/outline-ui/CHANGELOG.md`](bins/outline-ui/CHANGELOG.md) | [`CHANGELOG.ru.md`](bins/outline-ui/CHANGELOG.ru.md) |
| **Android app** | [`android/CHANGELOG.md`](android/CHANGELOG.md) | [`CHANGELOG.ru.md`](android/CHANGELOG.ru.md) |

Both binaries were at **1.9.0** (released 2026-08-24 under the pre-rename tags
`ss-v1.9.0` / `ws-v1.9.0`), alongside `outline-ui` **1.2.0** and the Android
app **1.2.0** from the same cut, before the workspace unified on CalVer
(`v26.11.0`) and renamed the crates to `outline-server` / `outline-client`.
Adaptive carrier
padding, TUN GSO / GRO / USO offload, and connection sniffing with destination
override all shipped earlier in this line. The headline recent work spans the
whole system:

- **BREAKING: server carrier endpoints unified (`outline-server`, pending
  release).** The `[websocket]` block, per-user `ws_path_tcp` / `ws_path_udp` /
  `ws_path_vless` / `xhttp_path_*` fields, and `[padding] enabled` / `paths`
  are removed and now fail to parse. Every carrier path is a single
  `[[endpoint]] { path, kind, padded }` entry in one global list, and users
  are pure credentials that work on every endpoint of their kind — padding is
  an endpoint attribute, not a separate path list. See
  [`bins/outline-server/README.md`](bins/outline-server/README.md#endpoint-model)
  and [`docs/PADDING.md`](docs/PADDING.md); migrate `config.toml` before
  upgrading.
- **Server mesh cluster.** Edge nodes relay a client's session to the home node
  that owns it, with per-outcome relay metrics and full session migration across
  an edge switch — single-target UDP, VLESS-mux bundles included.
- **Share-link everything.** Combined-path Shadowsocks users get an `ss://…`
  share link alongside the `vless://…` artifacts, and the client can describe a
  whole uplink — or a single fallback wire — from one share-link URI.
- **Deterministic synchronized re-selection** (`load_balancing.reselect_sync`)
  so a cloned node pair rotates onto the same uplink and leaves from one egress.
- **An Android VPN client** ([`android/`](android/)) reusing the `outline-client`
  uplink stack unchanged — now with an in-app tunnel status card (duration,
  traffic, active carrier), a build-version footer, and a signed-APK release
  pipeline (`vYY.M.PATCH` unified releases, rolling `android-nightly`) — plus the
  **`outline-ui`** aggregating dashboard service.
- **A Windows client** ([`bins/outline-windows/`](bins/outline-windows/)) on Tauri v2
  + Svelte 5 supporting SOCKS5 and TUN (Wintun) modes, built-in auto-updater with
  SHA-256 verification against `SHA256SUMS.txt`, zip-slip protection, and
  automatic tunnel reconnect.

See each binary's changelog for the full, version-by-version detail.

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*
