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

Both binaries are currently at **1.5.1** (2026-06-15). The headline `Unreleased`
change on both sides is **adaptive carrier padding** for the WS / XHTTP carriers
(anti TLS-in-TLS record-size correlation) — see each binary's changelog for the
server (per-path) and client (global) halves.

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*
