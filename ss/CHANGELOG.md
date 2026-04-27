# Changelog

All notable changes to this project are documented in this file.

This changelog is based on the repository history and stable git tags `v1.0.0`, `v1.0.1`, and `v1.0.2`. The repository also uses a `nightly` tag for channel publishing; those changes are grouped below under the corresponding stable release or the current unreleased section.

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*

## Unreleased

Changes after `v1.0.2` (2026-04-12):

### Added

- Added `tuning.ws_data_channel_capacity` to make the per-session WebSocket writer fan-in bounded mpsc capacity configurable. Defaults: `16` / `64` / `128` for `small` / `medium` / `large` profiles. The previous hard-coded `16` was sized for memory-constrained multi-session deployments and starved high-bandwidth single-tenant TUN clients during bursty video traffic — short WS-writer stalls back-pressured the upstream TCP read and the player's playback buffer underran. The default profile (`large`) now restores adequate throughput headroom; memory-constrained deployments can set the override to `16` to keep the prior behaviour.
- Added cross-transport session resumption for SS-over-WebSocket, single-target VLESS-over-WebSocket, single-target VLESS-UDP over WebSocket, VLESS mux over WebSocket, SS-UDP over WebSocket and **VLESS-TCP over raw QUIC** (opt-in via `[session_resumption]`, off by default). When enabled, the server mints a 16-byte Session ID, returns it in the `X-Outline-Session` response header on WebSocket Upgrade (HTTP/1.1, HTTP/2, HTTP/3), and parks the live upstream into an in-memory orphan registry on disconnect instead of tearing it down. A subsequent connect on any WebSocket transport carrying `X-Outline-Resume: <hex>` re-attaches to the parked upstream after authenticating the same user, skipping the upstream connect. For VLESS mux the entire `MuxState` — every TCP and UDP sub-connection inside it — is parked **atomically**; UDP sub-conns are reattached via the shared socket reference (no back-buffer, packets in-flight while parked may be dropped, matching UDP loss-tolerance). Single-target VLESS-UDP works the same way: the connected `UdpSocket` is preserved across the WS reconnect along with the partial 2-byte-length-prefixed frame buffer. SS-UDP-over-WS streams are connectionless across the WebSocket — one stream may register multiple `(user, fwmark, target)` NAT entries — so park snapshots the *list of NAT keys* this stream owns and detaches its sender from each (`detach_session_for_stream` is matched by a stream-unique `u64` so a concurrent reconnect cannot trample the slot); resume re-points each surviving entry at the new sender on the first authenticated datagram, without re-binding any upstream socket. Raw-QUIC has no HTTP headers, so the negotiation rides inside the VLESS request Addons TLV: tag `0x10 RESUME_CAPABLE`, tag `0x11 RESUME_ID`; the response carries `0x10 SESSION_ID` and `0x11 RESUME_RESULT`. Raw-QUIC TCP parks under the same `Parked::Tcp(Vless)` shape used by VLESS-over-WS, so a client that loses raw QUIC can fall back to VLESS-over-WS and resume the same upstream transparently. The parked entry records which proxy protocol authenticated the original session — cross-protocol or cross-shape resume requests (SS↔VLESS, single↔mux, tcp↔udp, ss-udp↔vless-udp) are rejected. Direct SS-UDP (no WebSocket tunneling) remains out of scope by spec. Owner-mismatched resumes are reported externally as `unknown` to avoid an existence oracle. Per-user (`orphan_per_user_cap = 4`) and global (`orphan_global_cap = 10000`) caps bound memory; a periodic sweeper evicts entries past `orphan_ttl_tcp_secs` (default 30 s). New metrics: `outline_ss_orphan_park_total{kind}`, `_resume_hit_total{kind}`, `_resume_miss_total{reason}`, `_evicted_total{kind,reason}`, `_current{kind}` — `kind` is `tcp`, `vless_udp_single`, `vless_mux` or `ss_udp_stream`. UDP single-target and raw-QUIC paths remain out of scope; see `docs/SESSION-RESUMPTION.md` for the wire format and roadmap.
- Added raw VLESS-over-QUIC and Shadowsocks-over-QUIC (no WebSocket, no HTTP/3 framing). The same `h3_listen` QUIC endpoint multiplexes them by ALPN: a new `[server.h3].alpn` list (default `["h3"]`) selects the protocols advertised — `h3` keeps the existing HTTP/3 + WebSocket-over-HTTP/3 path, `vless` carries one VLESS request per QUIC bidi stream (TCP target spliced on the stream; UDP target uses the bidi stream as a control/lifetime anchor and exchanges packets as QUIC datagrams prefixed with a 4-byte big-endian session_id), `ss` carries one SS-AEAD TCP session per bidi stream and one SS-AEAD UDP packet per QUIC datagram (routed through the same NAT table and replay store as the plain UDP listener). Adds the `quic` protocol label to existing metrics. The `mux.cool` VLESS command is rejected on raw QUIC — open additional QUIC streams instead.
- Added VLESS mux.cool / XUDP support over WebSocket: TCP and UDP sub-connections share a single VLESS stream (xray/happ/hiddify-compatible), with per-packet destination addressing on Keep frames and up to 8 concurrent sub-connections per session. The XUDP `GlobalID` is parsed but cross-connection session reuse is not yet wired.
- Added configurable H2/H3 resource tuning profiles (`small`, `medium`, `large`) with optional per-field `[tuning]` overrides.
- Added process-wide `udp_max_concurrent_relay_tasks` semaphore for capping concurrent UDP relay tasks.
- Added Grafana panel for UDP relay drops broken down by transport, protocol, and drop reason.
- Added cooperative graceful shutdown on `SIGTERM` and `SIGINT`.
- Added install-script version checks and nightly commit SHA resolution.
- Added regression coverage for WebSocket and HTTP/3 UDP NAT reconnect behavior.
- Added a Russian translation for `PATCHES.md`.
- Added randomized upstream IPv6 source selection from a configured prefix or interface.
- Added bounded TLS listener with graceful drain on shutdown.
- Added periodic WebSocket Ping (every 60s) over TCP to keep client `WS_READ_IDLE_TIMEOUT` alive.
- Added DNS singleflight to coalesce concurrent misses on the same host/port, with test coverage for coalescing and error recovery.
- Added a Grafana panel for UDP replay drops by user and protocol.

### Security

- Added Shadowsocks-2022 UDP anti-replay: duplicate `packet_id`s within the session window are rejected by a per-session 1024-bit sliding bitmap keyed by client session ID (so replays to a different target cannot bypass the filter). Drops are exposed as `outline_ss_udp_replay_dropped_total{user,protocol}`.
- Hardened root HTTP authentication with a constant-time password compare and removed a redundant derivation step on the auth hot path.
- Capped the Shadowsocks stream AEAD nonce counter at 2^32 invocations per direction to stay within AEAD safety limits.
- Bounded the HTTP/3 listener with two semaphores to prevent DoS via unbounded task fan-out: connection accepts are capped at 4096 (matching the TLS/shadowsocks listeners), and per-stream WebSocket handlers are capped globally at 65536 across all QUIC connections. Previously a client could open many QUIC connections and multiply per-connection stream limits into unbounded `tokio::spawn` fan-out.
- Capped the SS-2022 anti-replay session store via `tuning.udp_replay_max_sessions` (profile defaults 16k/64k/256k; `0` disables). Previously a client with a valid key could rotate `client_session_id` on every packet and inflate the store unbounded until the next idle sweep. Drops at the cap are exposed as `outline_ss_udp_replay_store_full_dropped_total{user,protocol}`.
- Moved config file persistence on control-plane mutations off the tokio worker: the user list mutex is now a `tokio::sync::Mutex` and `persist_users` runs via `spawn_blocking`, so a slow-disk write (NFS, USB) no longer stalls the runtime while the lock is held.
- VLESS-over-WebSocket now sends a graceful WebSocket Close frame on parser/auth failure instead of dropping the channels silently. Previously a probe with a wrong VLESS version byte or unknown UUID got an abrupt FIN/RST without any RFC 6455 Close — a sharp signature that distinguishes VLESS from a benign WebSocket endpoint and from the SS-over-WS path (which already sent a Close on auth failure). Upstream TCP/UDP connect failures still map to Close 1013 (Try Again Later); parser/auth failures map to a plain Close, mirroring the SS path.
- Added a probe-resistance sink on rejected handshakes for VLESS and Shadowsocks across WebSocket, plain TCP and raw-QUIC transports. After a parser/auth rejection the connection is held open and inbound traffic is drained to /dev/null until the existing handshake timeout (`SS_TCP_HANDSHAKE_TIMEOUT_SECS = 30`) or a 64 KiB byte cap fires; only then does the close arrive. This collapses the close-timing fingerprint that previously distinguished VLESS (parser bails on the 18th byte) from SS (AEAD path stalls until enough bytes for an authenticated frame) from a benign endpoint. Sinked sessions are reported in metrics as `disconnect_reason="handshake_rejected"`, split out from `error` so genuine relay errors are not skewed by the long sink-mode lifetime.

### Changed

- Moved tuning parameters (`client_active_ttl_secs`, `udp_nat_idle_timeout_secs`, `udp_max_concurrent_relay_tasks`) from top-level config fields into `TuningProfile` inside `[tuning]`. **Breaking change**: configs with old top-level keys fail on `deny_unknown_fields`.
- Renamed the per-user `vless_ws_path` config key to `ws_path_vless` for parity with `ws_path_tcp` / `ws_path_udp`. The control-plane JSON field and dashboard form use the new name as well. **Breaking change**: configs and API clients using the old name fail on `deny_unknown_fields`.
- Split the metrics module into focused submodules (`labels`, `registry`, `guards`, `sampler`, `render`).
- Consolidated transport session lifecycle and error classification into shared helpers, eliminating duplicated match blocks across TCP/UDP and WS/H3 paths.
- Split large server, transport, crypto, and config modules into smaller submodules for maintainability.
- Migrated the metrics stack to `metrics` and `metrics-exporter-prometheus`.
- Decoupled UDP NAT internals from transport-specific response handling.
- Continued hot-path optimization work across DNS cache, crypto, route maps, and metrics labels to reduce allocations and lock contention, including a cached monotonic clock (shared atomic) and read-locked fast paths for NAT entry lookup and replay-window checks.
- Unified parts of server logging and general internal naming for clarity.
- Reduced TCP upstream connect timeout from 10s to 5s.
- Relaxed systemd sandbox to allow `AF_NETLINK` so `getifaddrs` works for outbound IPv6 interface selection.
- Documented outbound IPv6 prefix/interface options in the Russian README and sample configs.

### Fixed

- Fixed H3 internal stack errors being silently classified as client disconnects; they now surface as `DisconnectReason::Error`.
- Fixed QUIC connection cycling by adding server-side keep-alive pings.
- Fixed HTTP/3 double-write paths that could trigger `H3_INTERNAL_ERROR` during write and shutdown.
- Fixed NAT entry reuse when a client session reconnects.
- Fixed TCP-over-H3 teardown symmetry when the client closes the connection.
- Treated unknown-user decrypt attempts as a handled condition instead of surfacing them as server errors.
- Fixed NAT eviction to drop uninitialised cells, keeping the active-entries metric honest.
- Fixed UDP NAT idle timer to only refresh on delivered responses, preventing stuck entries from extending their lifetime.
- Fixed HTTP/3 to send WebSocket Close 1013 on upstream connect failure (parity with TCP path).
- Fixed config validation so `h3_max_concurrent_uni_streams` must be non-zero.
- Fixed `outbound_ipv6_interface` to bind to the addresses actually assigned to the interface instead of random hosts inside their /64, so inbound return traffic works under ordinary SLAAC/DHCPv6 without AnyIP routes or NDP proxying. Pairs with kernel privacy extensions (`use_tempaddr=2`) for per-connection source rotation.
- Fixed VLESS over HTTP/3: the H3 router never inspected the VLESS path set, so Extended CONNECT requests to any configured `vless_ws_path` were answered with 404. VLESS is now routed on H3 with parity to Axum (TCP, UDP, mux.cool/XUDP).

## 1.0.2 - 2026-04-12

### Added

- Added configurable HTTP root authentication realm support.
- Added `install.sh --help` output.

### Changed

- Changed the default HTTP root authentication realm text.
- Changed the installer behavior to avoid auto-starting the service on fresh installs.
- Changed installer updates to restart an already active service when appropriate.

### Fixed

- Fixed release asset URL parsing and guard logic in `install.sh`.
- Fixed deployment setups that reuse the same address for `listen` and `h3_listen`.
- Fixed the nightly release reset flow before publishing assets.
- Fixed the HTTP/2-over-TLS WebSocket listener.
- Fixed HTTP root authentication handling for root requests.
- Reduced noise from benign TLS handshake EOF logs.

## 1.0.1 - 2026-04-09

### Added

- Added installer support for release channels and pinned versions.
- Added Shadowsocks TCP handshake diagnostics.

### Changed

- Refactored the server module layout to prepare for further cleanup and reliability work.

### Fixed

- Fixed transient listener errors so they no longer terminate the accept loop.
- Hardened Shadowsocks connection acceptance.

## 1.0.0 - 2026-04-06

This release summarizes the project history from the initial commits on 2026-03-12 through the first stable tag.

### Added

- Added the initial production-oriented Rust implementation of a WebSocket-based Shadowsocks relay.
- Added WebSocket transport support for HTTP/1.1, HTTP/2 (RFC 8441), and HTTP/3 (RFC 9220).
- Added built-in TLS for HTTP/1.1 and HTTP/2, plus QUIC/TLS support for HTTP/3 deployments.
- Added multi-user routing, per-user paths, per-user cipher selection, and Linux `fwmark` support.
- Added Prometheus metrics, memory monitoring, and a ready-made Grafana dashboard.
- Added architecture documentation and a Russian `README`.
- Added Outline-compatible access key generation, including separate client config generation.
- Added Shadowsocks 2022 support and a plain Shadowsocks listener.
- Added relay regression tests and process memory metrics caching.
- Added musl build aliases and release workflow support for cross-platform builds.

### Changed

- Made listeners optional and clarified the listener configuration model.
- Refactored the NAT table and per-session caching, including deduplicated UDP NAT entry creation.
- Added DNS caching and multiple metrics-path optimizations.
- Reworked allocator and memory diagnostics, ultimately replacing jemalloc with mimalloc.
- Split the library entrypoint and tuned HTTP/2 UDP latency.
- Improved release automation, artifact naming, Zig pinning, and target installation steps.

### Fixed

- Improved QUIC and HTTP/3 throughput and reduced packet drops.
- Fixed handling of large Shadowsocks packets by splitting them correctly.
- Fixed stream nonce overflow handling.
- Removed unnecessary allocations in the TCP encryption hot path and DNS cache lookups.
- Cleaned up allocator-related linking and release workflow issues.
