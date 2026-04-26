# Changelog

All notable changes to this project are documented in this file.

This changelog was reconstructed retroactively from repository tags and commit history. It summarizes user-facing and operator-facing changes rather than every individual commit.

A rolling `nightly` tag also exists in the repository, but the top section below tracks the current branch state after `v1.1.0` instead of a mutable tag.

---

*Russian version: [CHANGELOG.ru.md](CHANGELOG.ru.md)*

## [Unreleased] - changes after `v1.1.0` (through 2026-04-24)

### Added

- Cross-transport session resumption — client side, end-to-end. WebSocket Upgrade requests over HTTP/1.1, HTTP/2 and HTTP/3 advertise `X-Outline-Resume-Capable: 1` so that an outline-ss-rust server with the matching feature enabled mints a Session ID and returns it via `X-Outline-Session`. The ID is surfaced on `WsTransportStream::issued_session_id()` and stashed in a process-wide `ResumeCache` keyed by uplink name. On the next on-demand TCP-WebSocket dial (`connect_tcp_ws_fresh` — fresh dial, pool empty), the cached ID is presented as `X-Outline-Resume: <hex>` so the server can re-attach to a parked upstream and skip the connect-to-target. Resume is opt-in on the wire (servers without the feature ignore the headers) and zero-overhead when disabled. The warm-standby refill path intentionally does NOT participate in caching — pooled connections are anonymous slots; only acquire-on-demand dials carry the resume token. A new `connect_websocket_with_resume` exposes the underlying primitive for callers that want explicit control. See `docs/SESSION-RESUMPTION.md` in outline-ss-rust for the wire format.
- Raw QUIC transport (`*_ws_mode = "quic"`): VLESS / Shadowsocks framed directly over QUIC bidi streams and datagrams (RFC 9221), no WebSocket / no HTTP/3. ALPN selects the protocol on a per-connection basis (`vless`, `ss`, `h3`); pairs with the matching listener in outline-ss-rust. Multiple sessions of the same ALPN to the same `host:port` share one cached QUIC connection. VLESS-UDP uses a per-target control bidi (server returns a 4-byte `session_id`) plus connection-level datagram demux. SS-UDP rides QUIC datagrams 1:1 with SS-AEAD packets. No fallback by design — dial / handshake failure surfaces as a normal uplink failure.
- `[[route]]` rules now accept a `files = [..., ...]` list in addition to the existing `file`; all paths are merged into the rule's CIDR set and each one is watched independently for hot-reload. Useful for keeping IPv4 and IPv6 GeoIP feeds in separate files.
- Split the HTTP surface into independent metrics and control planes; the control plane now requires bearer authentication and can be enabled with its own Cargo feature.
- Added `POST /switch` for manual active-uplink switching.
- Added connection limiting with a semaphore to protect the process under connection floods.
- Added graceful shutdown for background uplink loops.
- Added richer diagnostics: target addresses in `session_death`, propagated transport read diagnostics for TUN and TCP probe paths, and request counters for control and metrics HTTP endpoints.
- Added TCP keepalive probes to the userspace TUN stack so dead peers are detected instead of lingering in established state.
- WebSocket Close code `1013` is now treated as a retryable signal, on par with TCP RST.
- Continued the workspace split by extracting dedicated crates for transport, uplink management, TUN, routing, metrics, Shadowsocks crypto, and SOCKS5 protocol primitives. Split `outline-transport` further into `outline-net` + `outline-ss2022`.
- Added a built-in multi-instance dashboard at `/dashboard`, gated behind the `dashboard` Cargo feature. The dashboard process holds per-instance control tokens server-side and proxies `/control/topology` and `/control/activate` to each configured instance. Supports both `http://` and `https://` control endpoints, preserves URL prefixes for instances behind a reverse proxy, and exposes a configurable `dashboard.request_timeout_secs`.
- Dashboard UI: instance-centric layout, per-group balancing settings panel, themed sidebar with a dark default palette and runtime light/dark toggle (browser `theme-color` follows the active theme).
- Added a packaged Grafana control-plane dashboard (`grafana/dashboard/outline-ws-uplinks.json`) with an integration guide in `grafana/README.md`.

### Changed

- **Breaking config change for `transport = "vless"` uplinks.** The VLESS server exposes a single WS path (`ws_path_vless`) shared by TCP and UDP, so the client now takes a single `vless_ws_url` / `vless_ws_mode` pair instead of duplicated `tcp_ws_url`+`udp_ws_url` / `tcp_ws_mode`+`udp_ws_mode`. The old fields are rejected with an explicit parse error when `transport = "vless"`. CLI: new `--vless-ws-url` / `--vless-ws-mode` (`OUTLINE_VLESS_WS_URL` / `OUTLINE_VLESS_WS_MODE`). Migration: replace
  ```toml
  tcp_ws_url = "wss://host/path"
  udp_ws_url = "wss://host/path"
  tcp_ws_mode = "h2"
  udp_ws_mode = "h2"
  ```
  with
  ```toml
  vless_ws_url = "wss://host/path"
  vless_ws_mode = "h2"
  ```
  No alias / silent fallback; `transport = "ws"` and `transport = "shadowsocks"` are unaffected.
- Reworked configuration, bootstrap, proxy, UDP, metrics, and TUN internals to fit the workspace layout and smaller focused modules.
- Reduced hot-path overhead with lower-allocation DNS caching, boxed AEAD variants, finer-grained uplink status locking, non-blocking `AsyncFd` TUN I/O, less heap churn in UDP/TCP paths, a mutex-free UDP send path, SACK scoreboard without per-ACK cloning, sticky-route pruning moved off the connect hot path, coalesced `/metrics` scrapes, and lock-free standby-pool reads.
- Raised the WebSocket read idle timeout from 120s to 300s so long idle periods (e.g. while an upstream model is thinking) no longer evict otherwise healthy sessions.
- Capped concurrency on the HTTP control and metrics planes and bounded the SOCKS5 handshake to shrink the DoS surface.
- Switched more internal paths to direct workspace crate usage instead of root-level facades and aliases.

### Deprecated

- The flat uplink config layout (top-level `tcp_ws_url` / `[probe]` / `[[uplinks]]` / `[load_balancing]`) is now deprecated; the canonical form nests these under `[outline]` (`[[outline.uplinks]]`, `[outline.probe]`, `[outline.load_balancing]`). The old layout is still accepted and logs a deprecation warning on startup. Example configs and README were updated to the new form.

### Fixed

- Serialized Prometheus rendering to avoid concurrent scrape races.
- Made configuration validation fail fast when metrics or control settings are used without the matching Cargo features.
- Prevented SOCKS5 UDP client-address hijacking and ensured cached UDP routing decisions react to uplink health changes.
- Fixed lifecycle issues around shared H2/H3 connection garbage collection, active-uplink state persistence, silently dropped uplinks behind router NAT, and feature-gated tests.
- The TCP idle watcher is now refreshed on keepalive traffic, so keepalive-only sessions are no longer evicted as idle.
- Phase-1 uplink selection no longer penalises an uplink when the target itself is unreachable.
- Fixed dashboard load-balancing chip labels so they match the real load-balancing enum variants.
- Fixed SOCKS idle-timeout keepalive accounting so keepalive traffic correctly defers SOCKS-side idle eviction.

## [1.1.0] - 2026-04-17

### Added

- Added policy routing with `uplink_group` and `[[route]]` sections, hot-reloaded CIDR-backed rule lists, `direct` routing, and the `invert` rule flag.
- Added YAML configuration support together with example YAML files.
- Added persistence for the selected active uplink across restarts.
- Added `hev-socks5` UDP-in-TCP support.
- Added group-aware UDP routing, TUN routing through policy-selected groups, `direct_fwmark`, and group labels in metrics and Grafana dashboards.
- Promoted TUN support and `mimalloc` to first-class build features for the default server profile.

### Changed

- Reused shared HTTP/2 and HTTP/3 uplink connections to reduce reconnect churn and improve steady-state behavior.
- Hardened keepalive, probing, warm-standby, and timeout handling across WebSocket, H2, and H3 transports.
- Improved installers and deployment docs with safer first-install behavior, version-aware updates, and refreshed examples.
- Performed a large internal refactor of transport, config, proxy, and test layout into smaller modules.

### Fixed

- Reduced spurious chunk-0 failovers and stale standby reuse.
- Fixed multiple socket-leak and half-closed-session cases in probes, direct TCP, shared H2/H3 connections, and SOCKS TCP session teardown.
- Corrected H3 shutdown handling, dashboard queries, state-file bootstrap edge cases, and several routing/dispatch issues found during review.

## [1.0.2] - 2026-04-09

### Added

- Added chunk-0 failover handling for early TCP tunnel failures.
- Added `probe.tcp` support for speak-first TCP health checks.
- Added stronger probe diagnostics and better failure attribution during transport establishment.

### Changed

- Refined failover tie-breaking so cooldown state is respected until the upstream actually recovers.
- Reorganized transport, uplink, and `tun_tcp` code into smaller submodules.
- Aligned install scripts, Keenetic installer logic, and docs with the current release pipeline.

### Fixed

- Restored SOCKS failover and probe behavior after regression fixes.
- Fixed TCP relay and probe diagnostics issues.
- Fixed `jq` compatibility problems in the Keenetic installer.
- Stabilized standby validation test coverage and ensured DNS cache usage stayed consistent across the stack.

## [1.0.1] - 2026-04-07

### Added

- Added per-connection uplink and downlink chunk debug logs to help diagnose transport behavior.

### Fixed

- Fixed SS2022 handling so an empty initial response header payload is no longer treated as EOF.

## [1.0.0] - 2026-04-06

### Added

- First signed stable release of the Rust proxy for local SOCKS5 traffic over Outline-compatible WebSocket transports and direct Shadowsocks uplinks.
- Added HTTP/1.1 Upgrade, WebSocket over HTTP/2 (RFC 8441), and WebSocket over HTTP/3 (RFC 9220) transports with fallback between transport modes.
- Added multi-uplink failover and balancing with health probes, sticky routing, warm standby, runtime cooldowns, and an `auto_failback` toggle.
- Added SOCKS5 username/password authentication, direct Shadowsocks socket uplinks, Shadowsocks 2022 support, optional listeners, and IPv6-first dialing.
- Added Prometheus metrics, Grafana dashboards, and operational documentation.
- Added existing-TUN integration with `tun2udp`, IP fragment reassembly, ICMP handling, and a production-oriented stateful `tun2tcp` relay with validation and loss recovery work.
- Added router-focused build options, cross-compilation guidance, nightly/stable release workflows, versioned release artifacts, and legacy MIPS release support paths.

### Changed

- Tuned memory allocation and transport settings for lower UDP latency and more practical router builds.
- Refined startup, configuration loading, metrics serving, and transport internals as the project moved from prototype stage to its first stable release.

### Fixed

- Fixed early metrics, dashboard, buffer flushing, memory monitoring, H3/QUIC fallback, UDP cleanup, and listener-configuration issues.
- Reduced false runtime failure detection in idle UDP cleanup and stale standby TCP paths.
- Hardened reliability around crypto, proxy, transport, FD exhaustion handling, and router deployment packaging.
