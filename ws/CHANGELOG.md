# Changelog

All notable changes to this project are documented in this file.

This changelog was reconstructed retroactively from repository tags and commit history. It summarizes user-facing and operator-facing changes rather than every individual commit.

A rolling `nightly` tag also exists in the repository, but the top section below tracks the current branch state after `v1.1.0` instead of a mutable tag.

---

*Russian version: [CHANGELOG.ru.md](CHANGELOG.ru.md)*

## [Unreleased] - changes after `v1.1.0` (through 2026-04-20)

### Added

- Split the HTTP surface into independent metrics and control planes; the control plane now requires bearer authentication and can be enabled with its own Cargo feature.
- Added `POST /switch` for manual active-uplink switching.
- Added connection limiting with a semaphore to protect the process under connection floods.
- Added graceful shutdown for background uplink loops.
- Added richer diagnostics: target addresses in `session_death`, propagated transport read diagnostics for TUN and TCP probe paths, and request counters for control and metrics HTTP endpoints.
- Continued the workspace split by extracting dedicated crates for transport, uplink management, TUN, routing, metrics, Shadowsocks crypto, and SOCKS5 protocol primitives.

### Changed

- Reworked configuration, bootstrap, proxy, UDP, metrics, and TUN internals to fit the workspace layout and smaller focused modules.
- Reduced hot-path overhead with lower-allocation DNS caching, boxed AEAD variants, finer-grained uplink status locking, non-blocking `AsyncFd` TUN I/O, and less heap churn in UDP/TCP paths.
- Switched more internal paths to direct workspace crate usage instead of root-level facades and aliases.

### Fixed

- Serialized Prometheus rendering to avoid concurrent scrape races.
- Made configuration validation fail fast when metrics or control settings are used without the matching Cargo features.
- Prevented SOCKS5 UDP client-address hijacking and ensured cached UDP routing decisions react to uplink health changes.
- Fixed lifecycle issues around shared H2/H3 connection garbage collection, active-uplink state persistence, silently dropped uplinks behind router NAT, and feature-gated tests.

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
