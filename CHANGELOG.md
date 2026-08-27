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
| **Dashboard** (`outline-ui`) | [`bins/outline-ui/CHANGELOG.md`](bins/outline-ui/CHANGELOG.md) | [`CHANGELOG.ru.md`](bins/outline-ui/CHANGELOG.ru.md) |
| **Android app** | [`android/CHANGELOG.md`](android/CHANGELOG.md) | [`CHANGELOG.ru.md`](android/CHANGELOG.ru.md) |

Both binaries are at **1.9.0**, released 2026-08-24 (tags `ss-v1.9.0` /
`ws-v1.9.0`), alongside `outline-ui` **1.2.0** and the Android app **1.2.0**
from the same cut. Adaptive carrier
padding, TUN GSO / GRO / USO offload, and connection sniffing with destination
override all shipped earlier in this line. The headline recent work spans the
whole system:

- **BREAKING: server carrier endpoints unified (`outline-ss-rust`, pending
  release).** The `[websocket]` block, per-user `ws_path_tcp` / `ws_path_udp` /
  `ws_path_vless` / `xhttp_path_*` fields, and `[padding] enabled` / `paths`
  are removed and now fail to parse. Every carrier path is a single
  `[[endpoint]] { path, kind, padded }` entry in one global list, and users
  are pure credentials that work on every endpoint of their kind — padding is
  an endpoint attribute, not a separate path list. See
  [`bins/outline-ss-rust/README.md`](bins/outline-ss-rust/README.md#endpoint-model)
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
- **An Android VPN client** ([`android/`](android/)) reusing the `outline-ws-rust`
  uplink stack unchanged — now with an in-app tunnel status card (duration,
  traffic, active carrier), a build-version footer, and a signed-APK release
  pipeline (`android-v*` tags, rolling `android-nightly`) — plus the
  **`outline-ui`** aggregating dashboard service.

See each binary's changelog for the full, version-by-version detail.

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*
