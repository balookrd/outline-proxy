# Changelog

All notable changes to this project are documented in this file.

This changelog was reconstructed retroactively from repository tags and commit history. It summarizes user-facing and operator-facing changes rather than every individual commit.

A rolling `nightly` tag also exists in the repository, but the top section below tracks the current branch state after the latest tagged release instead of a mutable tag.

---

*Russian version: [CHANGELOG.ru.md](CHANGELOG.ru.md)*

## [Unreleased] - changes after `v1.3.1`

### Added

- VLESS-over-XHTTP packet-up client. Two modes are live:
  - `vless_mode = "xhttp_h2"` — XHTTP rides a single shared TCP+TLS+h2 connection per session.
  - `vless_mode = "xhttp_h3"` — XHTTP rides QUIC + HTTP/3 (gated behind the `h3` feature, which the default profile already enables). Pairs with the same outline-ss-rust listener as the h2 variant; the server's `xhttp_path_vless` route is reachable on the QUIC endpoint via the `h3` ALPN.

  Both modes generate a per-session random id used for both halves: the driver opens one long-lived GET (downlink) and pipelines POSTs (uplink) sequenced by `X-Xhttp-Seq`. The XHTTP carrier is exposed through the same `TransportStream` enum the WS variants use, so it slots into the existing dial dispatch and TUN / SOCKS pipelines unchanged. New uplink config field `vless_xhttp_url` carries the base URL — required when `vless_mode` is one of the `xhttp_*` variants. Useful when WebSocket upgrades are blocked on the network path (Cloudflare-style CDN, captive-portal middleboxes).

  Three additional capabilities ride on the same dial path:
    1. **`xhttp_h3 → xhttp_h2` fallback.** When the QUIC + HTTP/3 dial fails (handshake timeout, ALPN mismatch, network-blocked UDP), the dispatcher transparently retries via h2 carrying the same `resume_request`, opens the existing `mode-downgrade` cooldown so subsequent dials skip h3 until recovery, and surfaces the originally-requested mode through `TransportStream::downgraded_from()` for the uplink-manager to record.
    2. **Cross-transport resumption** through the XHTTP carrier. The dial advertises `X-Outline-Resume-Capable: 1` and (when present) `X-Outline-Resume: <hex>`, then waits synchronously for the response headers so the server-issued `X-Outline-Session` is captured before the body drain starts. The token plugs into the existing `ResumeCache` exactly like the WS path, so a parked VLESS upstream re-attaches across an XHTTP reconnect — including the carrier-switch case (h3-failed-then-h2 carries the same token end-to-end).
    3. **Stream-one carrier** selected purely from the dial URL. Writing `?mode=stream-one` in `vless_xhttp_url` swaps the GET+POST pair for a single bidirectional POST whose request body is the uplink and whose response body is the downlink. No new config field, no new mode variant — `XhttpSubmode::from_url(&Url)` reads the query at dial time and routes to the matching driver. On h3 the stream is split via `RequestStream::split` so uplink and downlink halves run on dedicated tasks. The packet-up driver remains the default for URLs without (or with `?mode=packet-up`) the query.
- VLESS share-link URIs are now a first-class config shape. A single `link = "vless://UUID@HOST:PORT?type=ws|xhttp|quic&...#NAME"` entry inside `[[outline.uplinks]]` (or top-level / `[outline]` inline) expands at load time into the matching `vless_id` / `vless_*_url` / `vless_mode` triple, with `transport = "vless"` implied. Recognised query parameters: `type` (`ws` / `xhttp` / `quic`), `security` (`none` / `tls` / `reality`), `path`, `alpn` (selects H1 / H2 / H3 mode variant), `mode` (`packet-up` / `stream-one`, propagated to the XHTTP dial URL), and `encryption=none`. `flow=...`, `type=tcp|grpc|h2`, divergent `sni=` / `host=`, and any non-`none` `encryption` are rejected. The same field is accepted by the CLI flag `--vless-link <URI>` (`OUTLINE_VLESS_LINK`) and the `/control/uplinks` REST endpoints (`link`, alias `share_link`). See docs/UPLINK-CONFIGURATIONS.md "VLESS share-link URIs".

### Changed

- **Breaking config / CLI / API rename.** The transport-mode fields are now `tcp_mode` / `udp_mode` / `vless_mode` everywhere — TOML config (`tcp_mode = "h2"`), CLI (`--tcp-mode`, `--udp-mode`, `--vless-mode`), env vars (`OUTLINE_TCP_MODE`, `OUTLINE_UDP_MODE`, `OUTLINE_VLESS_MODE`), control-plane JSON (`/control/topology`, `/control/uplinks`), dashboard payload, and Rust API (`UplinkConfig::tcp_mode`, `effective_tcp_mode()`). Old `*_ws_mode` names are removed without aliases — existing TOML files and scripts must be renamed by hand. Reason: with `xhttp_h2` / `xhttp_h3` / `quic` no longer riding only WebSocket, the `_ws_` infix had become misleading.
- Dashboard panel now correctly renders `xhttp_h3` → `xhttp_h2` downgrades (previously the H3/QUIC downgrade decoration only fired on the legacy short-form mode strings, leaving xhttp uplinks visually frozen on the configured mode). VLESS uplinks now publish `tcp_mode` / `udp_mode` for `xhttp_h2` / `xhttp_h3` modes too — previously the field was emitted only when `vless_ws_url` was set, so XHTTP-only uplinks fell back to the default rendering ("VLESS/WS/H1").
- `outline_transport::install_test_tls_root(CertificateDer)` — test-only knob that pins a custom self-signed root for the XHTTP h2 / h3 dial paths. The override slot is a `RwLock<Option<…>>` defaulting to `None`, so production callers (which leave it unset) keep the existing webpki behaviour with one extra read per dial. The motivating consumer is the cross-repo end-to-end test in `outline-ss-rust`, which spins up an in-process self-signed server and dials it through the regular `connect_websocket_with_resume` entry.
- Test-mode bypass for the process-wide QUIC endpoint caches. When the test override is set (i.e. `install_test_tls_root` has been called), `H3_CLIENT_ENDPOINT_V4` / `_V6` and the raw-QUIC `QUIC_CLIENT_ENDPOINT_V4` / `_V6` skip the cache and bind a fresh endpoint per dial. Each `#[tokio::test]` runs in its own runtime; the cached endpoint's driver task is bound to whichever runtime first hit the cache, so it dies the moment that test ends and the next test sees `endpoint driver future was dropped`. Production behaviour is unchanged.

### Fixed

- WebSocket-over-h2 dialer was sending `:path = //{ws_path}` because `H2Dialer::open_on` formatted `target_uri` as `format!("{scheme}://{auth}/{path}")` while `websocket_path` already returns a leading `/`. Server-side axum routers reject the doubled slash with 404, which the WS-h2 dispatcher silently masked for years by falling back to h1 (tungstenite's URL handler normalises the slash on its way to the wire). The h2 path now concatenates without re-adding the slash. Visible only on h2-only servers (RFC 8441 stacks that don't speak h1) and surfaced by the cross-repo h3→h2 fallback test in `outline-ss-rust`.
- XHTTP h3 stream-one closed the QUIC connection with `H3_NO_ERROR` before any application bytes flowed: the only `SendRequest` was being moved into `open_h3_stream_one`, which dropped it on return, and the h3 crate's `SendRequest::drop` triggers a graceful close once `sender_count` hits zero. Mirrored the packet-up pattern — clone before the open helper, hold the clone alive in the driver task. Same commit moves the quinn `Endpoint` into the driver task (the previous `let _endpoint_guard = endpoint;` only kept it alive for the function body, not the session lifetime).
- Dashboard Uplinks editor now exposes the full XHTTP triple (`vless_xhttp_url`, `vless_mode`, `vless_id`) so XHTTP uplinks can be created and edited from the UI without hitting `unknown field` 400s.
- VLESS probes / standby refill route through the same `vless_dial_url()` helper as the live data path, so probes that pick the XHTTP carrier no longer fall back to `vless_ws_url` when only `vless_xhttp_url` is configured.

## [1.3.1] - 2026-04-29

### Fixed

- Per-host `ws_mode_cache` downgrade cap is now cleared on a successful dial of the original requested mode and the default TTL is shorter, so a recovered H3/QUIC path is exercised again as soon as it becomes reachable instead of staying clamped for the legacy long window.

### Changed

- Internal cleanup: `h3_downgrade_*` Rust identifiers and metric labels renamed to `mode_downgrade_*` to match the unified H3 + raw-QUIC semantics introduced in v1.3.0 (the TOML / CLI key already accepts `mode_downgrade_secs` since v1.3.0; the `h3_downgrade_secs` alias remains). `outline-uplink` `utils.rs` split into per-domain modules; `error_text.rs` renamed to `error_classify.rs`; tests reorganised under the canonical `<dir>/tests/<basename>.rs` layout. No user-facing config or API changes.

## [1.3.0] - 2026-04-28

### Added

- Raw QUIC transport (`*_ws_mode = "quic"`): VLESS / Shadowsocks framed directly over QUIC bidi streams and datagrams (RFC 9221), no WebSocket / no HTTP/3. ALPN selects the protocol on a per-connection basis (`vless`, `ss`, `h3`); pairs with the matching listener in outline-ss-rust. Multiple sessions of the same ALPN to the same `host:port` share one cached QUIC connection. VLESS-UDP uses a per-target control bidi (server returns a 4-byte `session_id`) plus connection-level datagram demux; SS-UDP rides QUIC datagrams 1:1 with SS-AEAD packets. The dial URL is reused as a QUIC dial target — only `host:port` matters; the path is ignored.
- Raw-QUIC oversize stream-fallback. New ALPNs `vless-mtu` / `ss-mtu` carry oversized UDP datagrams that exceed the QUIC datagram limit on a server-initiated bidi (`accept_bi`) so that pathologically large UDP payloads still ride raw-QUIC instead of being silently dropped. Initial QUIC `initial_mtu` is bumped to 1400 to keep typical UDP traffic on the datagram fast path.
- Raw-QUIC dial-time fallback. On dial / handshake failure, raw-QUIC paths now fall back to WS over H2 (with H1 as a further fallback) and open the unified mode-downgrade window so subsequent dials skip QUIC until the recovery probe confirms QUIC is reachable again. Covers VLESS-TCP, VLESS-UDP, SS-TCP, and SS-UDP. Replaces the previous "no fallback by design" behaviour.
- VLESS-UDP hybrid mux: wraps the raw-QUIC mux in a thin envelope that pivots to WS over H2 on first-dial failure, calls `note_advanced_mode_dial_failure` to start the cooldown, and proxies downlink datagrams from whichever inner mux is currently active. A latched `quic_succeeded_once` flag prevents collapse to WS once a QUIC session has actually completed — runtime errors on a working QUIC session still propagate as real failures.
- Cross-transport session resumption — client side, end-to-end, across **all** uplink transports and modes:
  - TCP over WebSocket (HTTP/1.1, HTTP/2, HTTP/3): WebSocket Upgrade requests advertise `X-Outline-Resume-Capable: 1`; the server returns a Session ID via `X-Outline-Session`, which the client stashes in a process-wide `ResumeCache` keyed by uplink name. On the next on-demand TCP-WebSocket dial (`connect_tcp_ws_fresh` — fresh dial, pool empty), the cached ID is presented as `X-Outline-Resume: <hex>` so the server can re-attach to a parked upstream and skip the connect-to-target.
  - SS-UDP-WS: the same header pair applies on on-demand UDP-WebSocket dials, keyed by uplink in the same `ResumeCache`.
  - VLESS-TCP over raw QUIC: resume tokens are exchanged via VLESS Addons opcodes on the connect bidi (no HTTP headers on the QUIC path).
  - VLESS-UDP-WS / VLESS-UDP-QUIC: each per-target session inside `VlessUdpSessionMux` carries its own Session ID (`HashMap<TargetAddr, SessionId>` on the mux), so a mux fanning out to N targets can resume N parked upstreams independently.
  - Warm-standby refill remains anonymous — pooled connections are unidentified slots; only acquire-on-demand dials carry the resume token.
  - Resume is opt-in on the wire (servers without the feature ignore the headers / opcodes) and zero-overhead when disabled. See `docs/SESSION-RESUMPTION.md` in outline-ss-rust for the wire format.
- Built-in multi-instance dashboard improvements: per-instance topology now loads asynchronously and refreshes independently; the collapsed-panel state is persisted in `localStorage` so the layout survives a refresh; uplink switch reasons are surfaced inline; the encapsulation + transport-stack columns now show the active H3/QUIC auto-downgrade state at a glance; the uplinks editor exposes `vless_ws_url` / `vless_ws_mode` so VLESS uplinks can be created and edited from the UI; the dashboard uplinks page is now wired to `[[outline.uplinks]]` (the canonical layout) for CRUD.
- Global uplink failover now considers UDP probe / runtime health on UDP-capable active uplinks: a UDP-only failure can trigger a global failover even when TCP score still looks fine.
- `tcp_ws_mode` / `udp_ws_mode` / `vless_ws_mode` now accept `h1` as an alias for `http1` in both TOML config and CLI / env-var parsing, matching the `h2` / `h3` / `quic` short-form naming convention.

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
- `h3_downgrade_secs` (also accepted as `mode_downgrade_secs`) now governs both the H3 and the raw-QUIC downgrade windows on `transport = "ws"` and `transport = "vless"` uplinks. Either an H3 application error or a raw-QUIC dial / handshake failure opens the same per-uplink window; subsequent dials of either advanced mode are deferred to WS-over-H2 until the timer expires.
- Manual uplink switches (`POST /switch`, `POST /control/activate`, dashboard click) no longer revert on the first runtime failure; the chosen uplink stays pinned and runtime failures are escalated through the normal classifier instead of silently snapping back to a previous selection. All metric counters are reset on a manual switch so freshly-pinned uplinks start with a clean health window.
- `weight` is now a **hard** priority signal in `primary_order` and `failover_order`, not a soft hint folded into the latency score. Among healthy candidates the highest `weight` always wins; EWMA-derived score only ranks within the same weight band. Previously a deliberately downranked backup with a sufficiently fast probe RTT could outrank a higher-weight uplink because the score formula `(EWMA + penalty) / weight` let extreme RTT differences override weight. Failover and active-active selection now match the existing `initial_strict_order` and `auto_failback` paths, which already treated weight as a strict priority.
- VLESS UDP session-mux hot path moved off `tokio::Mutex` and onto `parking_lot::RwLock` with an atomic `last_use` timestamp; per-destination dials are single-flight via `OnceCell` to prevent stampedes when many flows target the same destination.
- Routing fast path skips the per-packet `has_any_healthy` probe when no rule sets a fallback target.
- Standby refill skips the TCP pool lookup entirely when the effective dial mode is raw QUIC (which has no per-connection pool).
- Transport-internal cleanup: `tcp/connect` shares one SS target-header send between paths; `tun/tcp` flow tables moved to `DashMap` with a dedicated `FlowScheduler`; the H2/H3 dial skeleton is unified behind a single `WsDialer` associated-type trait; route TCP/UDP fallback shares one `apply_fallback_strategy` helper.

### Fixed

- Dashboard: the per-instance hyper connection driver is now aborted when the proxy task ends, closing a control-API socket leak that accumulated under instance churn.
- Raw QUIC: the `VlessUdpDemuxer` Arc cycle that kept probe-driven QUIC connections alive after probe completion is broken; probes no longer pin connections beyond their natural lifetime.
- TUN: raw-QUIC TCP dials initiated from TUN flows now fall back to WS over H2 the same way they fall back from SOCKS5 flows; previously a TUN-side raw-QUIC failure surfaced as an immediate flow termination.
- TUN/transport: the VLESS UDP socket leak that surfaced as growing FD count under flow churn is closed via `AbortOnDrop` on the per-target session task plus a strict WS pong deadline.
- TCP failover: deferred phase-1 failures preserve the original error chain so the surfaced root cause (e.g. TLS handshake error inside an H2 stream open) is no longer swallowed by the wrapping "phase-1 failed" message.
- VLESS probes: HTTP / TCP-tunnel probes no longer prepend a SOCKS5 target prefix to the probe payload; the DNS probe and the WS-handshake probe both dispatch through the raw-QUIC path when the uplink is configured with `vless_ws_mode = "quic"`.
- Routing engine: build dependencies on `outline-routing::compile_routing_table` were tightened so the helper compiles with `tokio` rt/time as dev-deps only.

## [1.2.0] - 2026-04-24

### Added

- VLESS-over-WebSocket uplinks (`transport = "vless"`). Authenticates with a single `vless_id` (UUID) instead of a Shadowsocks cipher / password; shares the WSS dial plumbing with `transport = "ws"`. VLESS UDP rides a per-destination session-mux (one WSS session per target inside the uplink) bounded by `vless_udp_max_sessions`, idle-evicted via `vless_udp_session_idle_secs`, with a configurable LRU evictor cadence (`vless_udp_janitor_interval_secs`). A real VLESS DNS data-path probe is wired in alongside the existing WS / HTTP probes.
- Built-in multi-instance dashboard at `/dashboard`, gated behind the `dashboard` Cargo feature. The dashboard process holds per-instance control tokens server-side and proxies `/control/topology` and `/control/activate` to each configured instance. Supports both `http://` and `https://` control endpoints, preserves URL prefixes for instances behind a reverse proxy, and exposes a configurable `dashboard.request_timeout_secs`. The UI is instance-centric with a per-group balancing settings panel, themed sidebar with a dark default palette and runtime light/dark toggle (browser `theme-color` follows the active theme), and a dedicated uplinks-configuration page that performs CRUD via `POST /control/uplinks` + `POST /control/apply` for hot-swap. (The earlier experimental Grafana control-plane dashboard prototype was retired in favour of the in-process UI.)
- Independent HTTP control plane. Mutating endpoints (`/switch`, `/control/topology`, `/control/summary`, `/control/activate`, `/control/uplinks`, `/control/apply`) live on a separate listener gated by mandatory bearer authentication and a dedicated Cargo feature; `/metrics` keeps its read-only role.
- `POST /switch` for manual active-uplink switching, plus `POST /control/activate` (JSON body) for the dashboard click path.
- `[[route]]` rules now accept a `files = [..., ...]` list in addition to the existing `file`; all paths are merged into the rule's CIDR set and each one is watched independently for hot-reload. Useful for keeping IPv4 and IPv6 GeoIP feeds in separate files.
- Connection limiting via semaphore on the SOCKS5 accept loop and on the HTTP listeners to protect the process under connection floods.
- Graceful shutdown for background uplink loops; in-flight connections are cancelled on SIGTERM so restarts come up faster.
- Richer diagnostics: target addresses in `session_death`, propagated transport read diagnostics for TUN and TCP probe paths, and request counters for the control and metrics HTTP endpoints.
- TCP keepalive probes on the userspace TUN stack so dead peers are detected instead of lingering in established state.
- WebSocket Close code `1013` (`Try Again Later`) is now treated as a retryable signal, on par with TCP RST.
- Continued the workspace split by extracting dedicated crates for transport, uplink management, TUN, routing, metrics, Shadowsocks crypto, and SOCKS5 protocol primitives. Split `outline-transport` further into `outline-net` + `outline-ss2022`.
- `--migrate-config` CLI for one-shot in-place migration of legacy top-level uplink keys into the canonical `[outline]` layout; the regular start path also auto-migrates with a deprecation warning.

### Changed

- TOML is now the only supported configuration format; the YAML loader and example files are removed.
- Reworked configuration, bootstrap, proxy, UDP, metrics, and TUN internals to fit the workspace layout and smaller focused modules.
- Reduced hot-path overhead with lower-allocation DNS caching, boxed AEAD variants, finer-grained uplink status locking, non-blocking `AsyncFd` TUN I/O, less heap churn in UDP/TCP paths, a mutex-free UDP send path, SACK scoreboard without per-ACK cloning, sticky-route pruning moved off the connect hot path, coalesced `/metrics` scrapes, and lock-free standby-pool reads.
- Raised the WebSocket read idle timeout from 120s to 300s so long idle periods (e.g. while an upstream model is thinking) no longer evict otherwise healthy sessions.
- Capped concurrency on the HTTP control and metrics planes and bounded the SOCKS5 handshake to shrink the DoS surface.
- Switched the systemd unit from `DynamicUser=true` to a fixed `outline-ws` system user so state files keep a stable owner across restarts; the install script now provisions the user and writable state directory.
- Switched more internal paths to direct workspace crate usage instead of root-level facades and aliases.

### Deprecated

- The flat uplink config layout (top-level `tcp_ws_url` / `[probe]` / `[[uplinks]]` / `[load_balancing]`) is now deprecated; the canonical form nests these under `[outline]` (`[[outline.uplinks]]`, `[outline.probe]`, `[outline.load_balancing]`). The old layout is still accepted, auto-migrated on startup, and logs a deprecation warning. Example configs and README were updated to the new form.

### Fixed

- Serialized Prometheus rendering to avoid concurrent scrape races.
- Made configuration validation fail fast when metrics or control settings are used without the matching Cargo features.
- Prevented SOCKS5 UDP client-address hijacking and ensured cached UDP routing decisions react to uplink health changes.
- Fixed lifecycle issues around shared H2/H3 connection garbage collection, active-uplink state persistence, silently dropped uplinks behind router NAT, and feature-gated tests.
- The TCP idle watcher is now refreshed on keepalive traffic, so keepalive-only sessions are no longer evicted as idle.
- Phase-1 uplink selection no longer penalises an uplink when the target itself is unreachable.
- Fixed dashboard load-balancing chip labels so they match the real load-balancing enum variants.
- Fixed SOCKS idle-timeout keepalive accounting so keepalive traffic correctly defers SOCKS-side idle eviction.
- Configuration loading now falls back to read-only mode gracefully when the target directory is read-only (e.g. `/etc/` under `ProtectSystem=strict`); the warning is logged and the process continues without persistence.

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
