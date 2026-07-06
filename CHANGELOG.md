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

The **server** (`outline-ss-rust`) is at **1.6.0** (2026-07-01) and the
**client** (`outline-ws-rust`) at **1.6.1** (2026-07-02); adaptive carrier
padding shipped in the 1.6 line. The headline recent work is on the client
data plane — **TUN GSO / GRO / USO offload** (`[tun] gso` / `gro` / `uso`) to
cut per-packet CPU, and **connection sniffing with destination override**
(TLS SNI / HTTP Host on TCP, QUIC ClientHello on UDP) so the exit node
resolves the real hostname — alongside long-RTT single-flow throughput fixes
(raised carrier receive windows + BBR congestion control, mirrored by the
server on its QUIC listener). See each binary's changelog for details.

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*
