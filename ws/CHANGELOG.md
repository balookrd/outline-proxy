# Changelog

All notable changes to this project are documented in this file.

This changelog was reconstructed retroactively from repository tags and commit history. It summarizes user-facing and operator-facing changes rather than every individual commit.

A rolling `nightly` tag also exists in the repository, but the top section below tracks the current branch state after the latest tagged release instead of a mutable tag.

---

*Russian version: [CHANGELOG.ru.md](CHANGELOG.ru.md)*

## [Unreleased] - changes after `v1.4.4`

### Added

- **`shuffle_wires` — per-uplink random forward-only wire rotation.** New boolean knob on `[[outline.uplinks]]`. When `true`, the wire chain `[primary, fallbacks…]` is reshuffled at config load and `PerTransportStatus::wires_failed_in_round` tracks per-round attribution; once every wire has been the active wire of a failed round since the last success, the uplink is reported runtime-failed so the load balancer fails over to another uplink instead of looping over a dead chain. Permutations are collision-free within an `[[uplink_group]]` (`shuffle_wire_chains_per_group`), so two same-shape uplinks in one group never land on the same chain — applied in both the legacy `load_uplinks` path and the new-shape `load_groups` path. Within a wire, the per-wire carrier stack walks down before the wire rotates (`xhttp_h3 → xhttp_h2 → xhttp_h1` first, then jump to the next wire) so a wire is only abandoned once its descent options are exhausted. Default `false`; existing configs keep the legacy operator-ordered chain and wrap-forever wire state machine bit-for-bit. `auto_failback`, `weight` and the active-wire / probe-recovery machinery remain orthogonal.

- **`shuffle_timer` — periodic active-wire reroll.** New `shuffle_timer = "1h"` knob on `[[outline.uplinks]]` (accepts `30s` / `5m` / `1h30m` / `2d` human-readable forms plus bare seconds). A per-uplink tokio task rerolls `active_wire` for both transports at every tick to a random wire of the chain, zeroes per-wire failure counters (`active_wire_streak`, `wires_failed_in_round`, `consecutive_failures`, `consecutive_runtime_failures`, `chunk0_consecutive_failures`), clears in-flight `mode_downgrade_*` caps, and pins the new wire for `mode_downgrade_duration` unless the roll lands back on primary. Probe-driven early-failback to primary in `record_transport_success` is suppressed while `shuffle_timer` is set — otherwise the next successful primary probe would snap `active_wire` back within seconds and the reroll would be invisible. Rotation is also driven by accumulated runtime + probe failures (gated to flip the uplink itself only when every wire of the round has failed). Interval surfaces on `UplinkSnapshot.shuffle_timer_secs`; reroll events fire `outline_ws_rust_uplink_failover_total{transport="tcp_shuffle_timer"|"udp_shuffle_timer"}`. Independent of `shuffle_wires` — the two can be combined or set independently. Round state and failed wires are surfaced on the dashboard.

- **Per-uplink `carrier_downgrade` opt-out.** New boolean on `[[outline.uplinks]]` (default `true`, preserving the legacy `h3 → h2 → h1` / `xhttp_h3 → xhttp_h2 → xhttp_h1` descent contract). Setting it to `false` collapses the vertical carrier cascade: `extend_mode_downgrade` returns immediately (no `mode_downgrade_*` state ever installs, no `↘` arrows on the dashboard, no `mode_downgrade_secs` window per rank), and `wire_is_at_carrier_floor` reports every wire as "at floor". Under `shuffle_wires = true` this turns the per-wire cascade into a direct wire-to-wire rotation — failures roll over on the very next `min_failures` threshold instead of spending one downgrade window per intermediate carrier first. Use case: DPI that drops the whole upstream regardless of HTTP version. `UplinkSnapshot.carrier_downgrade` is now always serialized on the snapshot (not skip-default) so operators can see the explicit setting.

- **TUN ICMP PMTUD synthesis on UDP oversize drops.** When a transport refuses an oversize UDP datagram, the TUN engine now synthesises an IPv4 "Fragmentation Needed" or IPv6 "Packet Too Big" reply (with the transport's reported `limit` as the advertised Next-Hop MTU, clamped to the protocol minimum of 576 v4 / 1280 v6), quoting the original IP + UDP header so the sender stack can match it back to the offending socket. Throttled at one PTB per second per flow (Linux `icmp_ratelimit`-equivalent; RFC 4443 §2.4(f) mandatory for ICMPv6, RFC 1812 §4.3.2.8 recommended for IPv4). Decision logic is extracted into a pure helper so the rate-limit policy can be unit-tested without the async flow-table machinery. Fixes the VoWiFi IKE_AUTH-with-certificates breakage over raw-QUIC where clients had no way to learn the effective tunnel MTU. New `cause` label on `udp_oversized_dropped_total` distinguishes the nine drop sites (`quic_dgram`, `vless_quic_dgram`, `vless_udp`, `ss_socket`, `socks_client`, `socks_relay`, `socks_direct`, `socks_in_tcp`) on the Oversized UDP Drops dashboard panel.

- **`tun.pmtud_emit_below_quic_initial` opt-in flag** (default `false`). The PTB synthesis above is gated on the transport limit being at least the family-specific QUIC Initial-datagram minimum (1200 for IPv4 / 1280 for IPv6) — sub-minimum oversize drops fall back to silent drop, otherwise a compliant QUIC stack receiving a PTB below the Initial minimum disables QUIC for the destination and falls back to TCP (regression caught in production: Samsung Smart-TV YouTube clients stopped switching streams from TCP to QUIC after the PMTUD code landed). Operators with no QUIC clients to protect (pure VoWiFi / IKEv2 concentrators carrying IKE_AUTH with certificates over a narrow raw-QUIC uplink) can flip the flag to `true` and get the explicit PMTUD signal on every sub-minimum drop. Above-minimum drops in the ~1300-1450 byte range (where real PMTUD breakage lives) keep emitting PTBs unchanged. Documented in `docs/TUN-PMTUD.md` / `docs/TUN-PMTUD.ru.md`.

- **`tun.ipsec_bypass` fast-path for UDP/{500,4500}.** Opt-in (default `false`). The TUN classifier only forwards TCP/UDP/ICMP, so raw ESP (IP protocol 50) is always dropped — VoWiFi / IKEv2 clients then fail to establish ESP-in-UDP even when the IKE handshake on UDP/500 and UDP/4500 succeeds. Setting `tun.ipsec_bypass = true` short-circuits both ports to `TunRoute::Direct` before policy routing, reusing the same local-socket path as `via = "direct"`. Both ports are matched together because `NAT_DETECTION` moves IKE_AUTH off port 500 mid-session. The direct path uses `SO_MARK = direct_fwmark` to escape the TUN routing loop; a startup warning fires when `ipsec_bypass = true` is set without `direct_fwmark` on Linux so split-tunnel vs default-route setups stay explicit.

- **Strict-mode SOCKS5 abort on active uplink switch.** Mirrors TUN's strict-mode behaviour in the SOCKS5 ingress: in `active_passive` mode (any routing scope), a manual control-plane switch or probe-driven failover that moves the active uplink off an in-flight session now forcibly tears that session down with TCP RST (`SO_LINGER {l_onoff=1, l_linger=0}`) so the client application reconnects through the new active uplink. UDP-side downlink loop subscribes to the same signal so transport replacement no longer waits for the next datagram. `UplinkManager` publishes an `ActiveUplinksSnapshot` over a `tokio::sync::watch` channel; `pinned_relay::run_relay` races the data tasks against the watcher and on switch returns `DriveExit::AbortedOnSwitch`; `udp::group::run_group_downlink` subscribes to `subscribe_active_uplinks` to wake the loop on `changed()`. New counter `outline_ws_rust_socks_tcp_strict_aborts_total`. Default behaviour for `active_active` unchanged — the watcher never arms there.

- **TCP retries route through the active wire** (per-wire runtime failure attribution). The mid-session retry orchestrator and the chunk-0 same-uplink recovery paths now dial whichever wire the manager currently considers active, not the unconditional primary URL. `connect_tcp_fallback_fresh` grew a `FallbackDialOptions` struct so the retry path can request Ack-Prefix / Symmetric Downlink Replay on a fallback wire identically to primary. New `report_runtime_failure_for_wire` wraps the existing accounting with the same "failure on a non-active wire is session-local churn" rule that `record_wire_outcome` already enforces on the dial path — mid-session resets, terminal chunk-0 failures and the deferred-failure flush now pin their failures to a wire; failures attributed to a wire the manager has already moved off are recorded only as a suppressed metric. Single-wire uplinks and the legacy uplink-level `report_runtime_failure` entry point keep bit-for-bit identical behaviour.

- **`[outline.probe.tls]` — TLS handshake-only data-path probe.** Drives `ClientHello → ServerHello / Certificate → Finished → close_notify` through the uplink tunnel against a configured `(SNI, port)` target, with no HTTP exchange after the handshake. Reproduces the user-flow `chunk0_timeout` failure pattern (handshake to the uplink server succeeds, ClientHello is forwarded to the upstream target, no response bytes ever come back) that the plain HTTP probe is blind to — `probe.http` only ever validates `http://...` and never exercises TLS, so an upstream filter that silently drops `ServerHello` records for specific SNIs leaves `uplink_health` stuck at `1` and the probe-driven escalation path never fires. Config is a rotation list of `"host:port"` strings (bare host defaults to port 443; IPv6 bracketed `"[::1]:443"`); the cursor advances one entry per cycle. Mutually exclusive with `[outline.probe.http]` / `[outline.probe.tcp]` inside one cycle (priority `tls → http → tcp`). Metrics emit `probe="tls"`. Implementation lives in `crates/outline-uplink/src/probe/tls.rs`; a public helper `outline_transport::build_https_probe_client_config` shares the rustls root-store / test-override plumbing with every other dial in the project. Documented in `docs/UPLINK-CONFIGURATIONS.md` "TLS handshake-only data-path probe".

- **Profile pool refresh (2026-05).** Bumped the six pool entries to the May-2026 current-stable browser releases: Chrome 142 (Windows + macOS), Firefox 150 (Windows + macOS), Safari 19 (macOS, patch 19.4), Edge 142 (Windows). Sec-CH-UA brand list versions follow Chrome / Edge majors. Chrome and Safari on macOS continue to pin the frozen `10_15_7` UA string per Google / Apple's design (real OS version moves to `Sec-CH-UA-Platform-Version`); Firefox uses the actual `Intel Mac OS X 16.4`. `PROFILES_REFRESHED_AT_UNIX` bumped from 2026-05-01 to 2026-05-09. Existing pool-id assertions updated to the new ids (`chrome-142-*`, `firefox-150-*`, `safari-19-macos`, `edge-142-windows`). Operators on dashboards / alerts pinning specific old ids (`chrome-130-macos`, etc.) must update — the fingerprint-strategy histogram / chip is unchanged in shape, only the rendered name moves.

- **`process_stable` fingerprint diversification strategy + alias change.** Adds `Strategy::ProcessStable` to the browser-fingerprint pool: one identity for the entire process, regardless of which uplink dials, mirroring how a real user with a single browser appears to an on-path observer. The pick is seeded from the OS-level hostname (`gethostname(2)` on Unix, `%COMPUTERNAME%` from the process env on Windows) for cross-restart stability on the same machine. **`$HOSTNAME` is not the seed source** — it is a shell-internal variable on Linux / macOS, not part of the process env, so daemons started by systemd / docker / cron never see it. In containers without an explicit `--hostname` the syscall returns no useful value and the seed falls back to `rand::random` at process start (stable in-process, rotates on restart). Adds `libc = "0.2"` to `outline-transport` dependencies. Prometheus label set extended to `none` / `per_host_stable` / `process_stable` / `random`.

- **Liveness override forces a probe pulse every N minutes** — closes the gap where an uplink whose probe-skip optimisation kept skipping (because a warm pipe was always fresh) would never re-validate after the operator-side path silently broke; the forced pulse re-arms the probe machinery on a deterministic schedule.

- **`skip_when_active` probe knob** to disable the probe-skip optimisation per uplink. By default the probe-cycle skips the WS / HTTPS sub-probes when a warm pipe already proves liveness; flipping `skip_when_active = false` re-enables explicit probing on every cycle for paranoid deployments.

- **Chunk-0 timeout streak escalates the active uplink** under slow-burn upstream failure. A dedicated counter — distinct from the runtime-failure window — escalates after the configured threshold of consecutive chunk-0 timeouts even when each individual session bails out on a fast cross-uplink fallback that masks the underlying primary degradation. WARN-level log surfaces silent cross-uplink chunk-0 failovers that would previously have been invisible to operators.

- **Per-uplink open-connection gauge + close classification** for leak detection. New Prometheus gauge `outline_ws_rust_uplink_open_connections{group,uplink,transport}` plus a `close_reason` label on the close counter, so half-closed-session and orphaned-driver leaks surface as a monotonically growing gauge instead of fading into the noise.

- **Mode-downgrade window metrics + hang-diagnostics dashboard.** Mode-downgrade window remaining seconds are published on Prometheus per uplink+wire+transport; a new Grafana dashboard section "Hang diagnostics" joins these with the chunk-0 timeout streak, mid-session retry counters, and the runtime-failure window so an operator triaging a slow-degradation reads everything from one panel.

- **Ack-Prefix Protocol v1 + v1.1 + v2 Symmetric Downlink Replay.** Mid-session retry foundation. Client and server exchange an Ack-Prefix control frame on the wire so the server knows how many uplink bytes the client has already received, and on a retry the server replays only the suffix the client hasn't acked. v1.1 makes the offset non-blocking and adds VLESS-WS support; v2 extends to **Symmetric Downlink Replay** — the client publishes a Down-Acked offset header (with XHTTP capability negotiation), so the retry replays starting from the client's last acked downlink offset rather than the whole session. Wired into `pinned_relay` through `connect_tcp_fallback_fresh`'s `FallbackDialOptions`. Operator knobs: `tcp_mid_session_retry_buffer_bytes`, `tcp_mid_session_retry_consume_timeout_secs`, `tcp_mid_session_retry_overflow_policy` (`soft` / `hard`). New Grafana dashboard section "Mid-session retries (v1+v2)"; `downlink_truncated` outcome documented under `record_mid_session_retry`.

- **WS-family hysteresis stack: multi-step H3 → H2 → H1 descent** plus WS-family mirror tests. Symmetric to the XHTTP family's `xhttp_h3 → xhttp_h2 → xhttp_h1` walk-down — a WS uplink configured at `h3` now properly cascades through `h2` to `h1` rather than stopping at one step, and the per-wire `mode_downgrade_capped_to` slot tracks the full descent.

### Changed

- **TUN direct UDP flows are now bounded by `tun.max_flows`.** Previously only tunnelled (`via = "group"`) UDP flows were capped; direct (`via = "direct"`) flows grew without limit, so a UDP storm to direct-routed destinations (P2P/DHT, scans) could spawn tens of thousands of per-flow sockets and reader tasks at once and push RSS far above the working set. The direct flow table now applies the same least-recently-seen eviction as the tunnelled table — `max_flows` bounds each table independently. Additionally, a direct flow's reader no longer holds a permanent 64 KiB receive buffer: it parks on socket readiness and allocates the buffer only while a datagram is in flight (`try_recv_buf_from`, no zeroing), so an idle direct flow costs no per-flow buffer and the burst high-water mark drops accordingly.

- **mimalloc builds periodically return freed memory to the OS.** A low-frequency background thread calls `mi_collect(true)` every 30 s. mimalloc purges freed pages lazily and only under allocator activity; after a large transient burst that then goes idle (e.g. a TUN UDP flow storm draining at once) nothing would otherwise drive the delayed purge, and RSS could stay pinned at its high-water mark for a long time. Forcing collection reclaims the empty segments, and decommit-on-purge (mimalloc default) hands the pages back to the kernel. Gated behind the existing `mimalloc` feature, so router builds are unaffected.

- **Idle relay/reader paths no longer pin a 64 KiB buffer per connection.** Following the TUN direct-UDP fix, the same allocate-on-ready pattern (park on socket readiness, allocate the receive buffer only while a datagram/segment is in flight via `try_read_buf` / `try_recv_buf`, release it before the next park) was applied to the remaining long-lived read loops: SOCKS5 direct TCP relay (both directions, `proxy/tcp/direct.rs`), the tunnelled SOCKS5 TCP uplink (`pinned_relay`), the tunnelled UDP `Socket` transport (raw Shadowsocks-over-UDP, `udp_transport.rs`), the TUN direct TCP upstream reader, the SOCKS5 UDP relay receive loops (uplink + direct downlink, `proxy/udp/socks5.rs`), and the UDP-in-TCP direct downlink (`proxy/udp/in_tcp.rs`). An idle connection/flow/association on these paths now holds no per-connection read buffer, cutting steady-state RSS when many connections are open but silent. Throughput-active connections are unaffected — the buffer is allocated exactly when data is ready. Tunnelled UDP over WS/QUIC was already buffer-free (datagrams arrive via an mpsc channel).

- **Breaking-ish: the bare `stable` alias now resolves to `process_stable` instead of `per_host_stable`.** The previous PerHostStable default would surface different browser identities for the same source IP across different hosts — a strong signal to any global on-path observer that the traffic is automated multi-pseudo-client (a real user keeps one browser). Configs spelling `stable` get the safer behaviour automatically; operators who specifically want the per-peer split must spell `per_host_stable` / `per-host-stable` / `per-host` in full. The Prometheus `strategy` label, snapshot JSON, and the dashboard chip switch from "per_host_stable" to "process_stable" for these configs — alerting / panels keying on the old token must be updated. `Strategy::PerHostStable` itself is intentionally retained, not removed: it remains correct for deployments where peers are fully decoupled across observers (different ASes, different jurisdictions, no global DPI).

- **HTML dashboard chip now shows the active fingerprint profile name** instead of the strategy token. Operators want to see *what is on the wire* (`Chrome 130 macOS`), not the configuration knob (`Stable`). The snapshot builder runs `select_with_strategy(primary_dial_url, effective_strategy)` for each uplink and ships the resulting profile id in the new `UplinkSnapshot::fingerprint_profile_name` field, forwarded through topology JSON with `skip_serializing_if = "Option::is_none"` for backward compatibility. `prettyProfileName` translates the kebab-case pool id (`chrome-130-macos`, `firefox-130-windows`, `safari-17-macos`, `edge-130-windows`) into a human label; `random` strategy surfaces as the literal token. Colour split unchanged: blue for stable profiles, purple for random.

- **Dashboard surfaces for the active fingerprint strategy** — Grafana stat panel "Fingerprint Strategy" in the top status row; per-uplink chip `FP: Stable` / `FP: Random` next to the protocol pill on every row whose effective strategy is non-default; uplinks on `none` get no chip. The fingerprint chip is hoisted into the group header when uniform across the group, and moved from the Protocol column to the Status column for legibility.

- **CLI / env override for the browser fingerprint diversification strategy**. The `--fingerprint-profile <off|stable|random>` flag (or `OUTLINE_FINGERPRINT_PROFILE`) shadows the top-level `fingerprint_profile` TOML key — same precedence as `--listen` / `--metrics-listen`, and per-uplink overrides still win on top of either source. Accepts the same alias set as the TOML key.

- **Prometheus / snapshot visibility for the active fingerprint strategy**. New gauge `outline_ws_rust_uplink_fingerprint_profile_strategy_info{group, uplink, strategy}` published unconditionally for every uplink — `1` on the active strategy and `0` on the others, label set fixed at `none` / `per_host_stable` / `random`. Reflects the **effective** strategy. The same string is exported on the `/snapshot` control endpoint via the new `UplinkSnapshot::fingerprint_profile_strategy` field.

- **Refactor: transport dial planning + uplink config loading.** `crates/outline-transport/src/dial_plan.rs` now exposes `TransportDialOptions` / `DialNetworkOptions` / `DialResumeOptions` / `connect_transport`; the facade in `lib.rs` stays thin. `src/config/load/uplinks/` is split into `source_precedence`, `credentials`, `wire_shape` and `fallback_resolution` modules with a thin `mod.rs` orchestration layer.

- **TUN cleanup**: flow eviction no longer performs an O(n) scan of the TUN TCP table; TUN metrics stubs now compile cleanly under `--no-default-features --features router`. Vendored `vendor/sockudo-ws` workspace member is now explicitly listed and documented.

- **Probe machinery fixes**: pin expiry no longer force-snaps active wire to primary; primary-probe escalation gated on active-fallback liveness, with fallback-wire probe failures propagated into the `active_wire` streak; `https://` URL targets accepted in `[probe.tls]` and rejected up-front in `[probe.http]`; `tls` included in `tcp_budget` for the probe-cycle outer timeout; `https` handshake metrics attributed under `probe="https"`; probe-cycle keeps running when the chunk-0 signal is fresh; stale `tun-tcp` and `native-burst` Grafana dashboards dropped; new "Probe vs User-Flow Correlation" dashboard row.

- **Dashboard polish**: shuffle round state + failed wires painted on the dashboard; carrier family surfaced on inactive fallback wire chips (e.g. `VLESS/WS › VLESS/XHTTP › SS/QUIC`) — active chip keeps the full `VLESS/XHTTP/H3` shape; group-header Active chip now tracks the actual active wire.

### Fixed

- **Control uplink apply hints** — the `/control/apply` hints surfaced misleading messages for some payloads; canonical hint flow restored.

- **`VlessTcpReader::read_chunk` returns the header-bundled tail** instead of dropping it on the floor — closes a silent data-loss path on the first read after a header-bundled VLESS frame.

- **Chunk-0 timeouts now classified under `cause = "timeout"` / `signature = "chunk0_timeout"`** in metrics, so the operator dashboards distinguish slow-burn failures from fast-fail dial errors.

- **`gethostname(2)` seeds ProcessStable**, not `$HOSTNAME` env — the latter is a shell-internal variable that systemd / docker / cron daemons never inherit, so the previous read produced `rand::random` fallback for every typical deployment (no in-process stability across restarts on the same machine).

## [1.4.4] - 2026-05-07

### Added

- **Per-uplink fallback transports via `[[outline.uplinks.fallbacks]]`.** Each `[[outline.uplinks]]` entry now accepts a list of fallback wires that the dial loop tries in order when the primary transport on this uplink fails. Each fallback carries its own `transport` (`ws` / `shadowsocks` / `vless`) plus the matching wire-shape fields; `cipher` / `password` / `fwmark` / `ipv6_first` / `fingerprint_profile` default to the parent uplink's value when omitted (VLESS `vless_id` is per-wire and not inherited). The TCP path (`connect_tcp_uplink` in `src/proxy/tcp/failover.rs`) and UDP path (`acquire_udp_with_fallbacks` in `src/proxy/udp/transport.rs`) wrap their primary dial in a fallback-aware loop: a successful fallback dial is invisible to the load-balancer beyond the `outline_uplink_selected` metric tick, and `report_runtime_failure` is bumped only when every wire on the uplink has failed. UDP candidate filter (`supports_transport_for_scope`) now consults `UplinkConfig::supports_udp_any()` so an uplink with a UDP-capable fallback shows up for UDP dispatch even when its primary is TCP-only.

- **Same-transport fallbacks** in `[[outline.uplinks.fallbacks]]`. The previous validator rejected fallbacks whose `transport` matched the parent uplink's primary (and rejected duplicate `transport` entries within the fallback list). Both rules were too tight — the most natural cross-family chain inside VLESS is `xhttp_h3 → ... → xhttp_h1` on a primary wire and `ws_h3 → ws_h2 → ws_h1` on a fallback wire, both with `transport = "vless"` but with different carrier families and different dial URLs. The relaxation lets operators write a VLESS-XHTTP primary plus a VLESS-WS fallback (or two SS fallbacks at distinct hosts).

- **Cross-transport fallback in the dial / chunk-0 failover loop.** The candidate list returned by `tcp_candidates` / `udp_candidates` / `tcp_failover_candidates` is now stably grouped by `UplinkTransport` (`vless` / `shadowsocks` / `ws`) in order of first appearance, while the relative order inside each group still reflects the underlying health/weight/score ranking. Consumers iterate the list with a shared `tried_indexes` set, so they now exhaust every endpoint of the leading transport before falling over to the next one — all VLESS uplinks are tried before any Shadowsocks/WS endpoint, and the cross-transport fallback only kicks in when a second transport is actually configured in the group.

- **Per-uplink active-wire state machine** with sticky-fallback and auto-failback. After `probe.min_failures` consecutive dial failures of the active wire, the dial loop advances `active_wire` to the next configured wire and pins it there for `LoadBalancingConfig::mode_downgrade_duration`. Subsequent new sessions start at the sticky wire instead of always retrying primary first; the dial chain is built by `wire_dial_order(uplink_index, transport, total_wires)` which starts at active and wraps so primary is still tried as a last resort even when active is pinned to a fallback. When the pin expires `active_wire` snaps back to `0` (primary). State is **per-transport** (TCP and UDP advance independently). New `crates/outline-uplink/src/manager/active_wire.rs` exposes `wire_dial_order` and `record_wire_outcome` on `UplinkManager`.

- **Wire-aware chunk-0 failover** (handover within uplink). The chunk-0 failover loop now tries every other wire on the *same* uplink before jumping to a different uplink; combined with the resume-cache participation below, the X-Outline-Resume token issued for the failed wire rides into the wire-handover dial so the chunk-0 replay buffer is *all* the client-visible change. `failover_to_next_candidate` is now two-phased: **Phase A** iterates `wire_dial_order` of the current uplink (tracked in `tried_wires_per_uplink: HashMap<usize, HashSet<u8>>` that survives cross-uplink jumps); **Phase B** is the previous cross-uplink failover, reached only when every wire on the current uplink has been tried. Wire-handover events surface on the failover counter under `transport="tcp_wire"`.

- **Resume-handover across wire switches on the same uplink.** Fallback TCP and UDP dials now participate in the cross-transport resume cache (`outline_transport::global_resume_cache()`) keyed on `<uplink_name>#<transport>` — the same identity-level key the primary path uses. Applies to WS↔WS, VLESS↔WS, VLESS↔VLESS, WS↔VLESS handovers. Shadowsocks fallback has no WS layer and no resume mechanism; it dials fresh.

- **Liveness override** for uplinks with `[[outline.uplinks.fallbacks]]` configured: when the probe has marked the parent uplink unhealthy because the *primary* wire is broken but a fallback wire has dialed successfully within `runtime_failure_window`, the uplink stays in the candidate set so the active-wire dial loop can keep using the working fallback. Implementation: new `PerTransportStatus::last_any_wire_success: Option<Instant>` stamped by `record_wire_outcome` on every successful wire dial, and new `selection::any_wire_recent_success` consulted by `selection_health` in both Global and per-flow / per-uplink scopes. The override is **gated on `!fallbacks.is_empty()`** so single-wire uplinks keep their probe-only health gating intact.

- **Probe-driven active-wire failover** for `active_passive`-passive uplinks. Symmetric pair of the probe-driven early-failback below: when the probe fails `probe.min_failures` consecutive times AND the uplink has at least one fallback configured AND the active wire is still primary, `active_wire` advances to wire 1 and gets pinned for `mode_downgrade_secs`. Critical for `active_passive` groups: the *passive* uplinks receive probes but no client traffic, so before this commit their `active_wire` state machine never moved.

- **Probe-driven early failback** for sticky active wires. When the parent uplink's primary wire has been pinned to a fallback after consecutive dial failures, the existing probe (primary-only in this iteration) now drives an early snap-back to primary as soon as it accumulates `probe.min_failures` consecutive successes — short-circuiting the auto-failback timer.

- **VLESS-as-fallback** on UDP for the WS family (`ws_h1` / `ws_h2` / `ws_h3`) and the XHTTP family (`xhttp_h1` / `xhttp_h2` / `xhttp_h3`) — both ride the same `VlessUdpSessionMux` carrier that the primary-VLESS UDP path uses. `dial_udp_fallback` builds the mux directly with the fallback's wire fields; the parent group's `vless_udp_mux_limits` and `udp_ws_keepalive_interval` keep fallback sessions on the same budgets as primary.

- **VLESS-as-fallback over raw QUIC** (`vless_mode = "quic"`). Closes the last hole in the fallback-transport surface — with per-wire mode-downgrade tracking now in place, the QUIC fallback's `on_fallback` / `on_downgrade` hooks write to *the fallback wire's* slot via `note_silent_transport_fallback_for_wire(parent.index, transport, wire_index, requested)`. Gated behind the workspace `h3` feature.

- **Per-wire mode-downgrade tracking** for fallback transports. New `PerTransportStatus::fallback_mode_downgrades: Vec<ModeDowngradeSlot>` (lazily extended on first write) gives every non-primary wire its own family-aware mode-downgrade window, completely separate from primary's `mode_downgrade_until` / `mode_downgrade_capped_to`. New `effective_tcp_mode_for_wire` / `effective_udp_mode_for_wire` and `note_silent_transport_fallback_for_wire` are wire-aware variants of the existing helpers. The fallback's downgrade follows the same family / monotonic-decrease rules as primary (`XhttpH3` → `XhttpH2` → `XhttpH1`; cross-family triggers are dropped).

- **Per-wire probe walks** validate fallbacks for passive uplinks — the probe machinery now exercises each configured fallback wire in turn rather than always hitting only primary, so a passive uplink whose primary is broken but whose fallbacks are healthy reports `effective_health = true` from the very first probe cycle.

- **Per-wire RTT EWMA** so scoring ranks the wire actually carrying traffic.

- **Active_wire advances on probe-machinery error**, not just on probe-confirmed wire failure — closes the gap where a probe stuck mid-handshake never produced a confirmed outcome.

- **Fallback wire dials feed RTT EWMA** so score-based selection between uplinks reflects the active wire's real latency. Previously fallback dials deliberately bypassed `report_connection_latency` so they wouldn't pollute primary's per-uplink statistics; the side effect was that with sticky-fallback active the EWMA stayed pinned to whatever the probe last measured on primary.

- **Effective health** ("visualization truth") on snapshots, Prometheus, and the dashboard. New `UplinkSnapshot::tcp_health_effective` / `udp_health_effective` fields evaluate to `Some(true)` when the probe-confirmed health is true OR — for uplinks with at least one fallback configured — when any wire has dialed successfully within `runtime_failure_window`. New Prometheus gauge `outline_ws_rust_uplink_health_effective{group,transport,uplink}`; the existing `outline_ws_rust_uplink_health` keeps its probe-only semantics. Topology endpoint serializes the new fields; the dashboard's `legHealth` / `healthy` helpers consult them so multi-wire uplinks with a working fallback render green even when probe of primary is failing.

- **Operator visibility** for the per-uplink active-wire state. New fields on `UplinkSnapshot`: `configured_fallbacks: Vec<String>`, `tcp_active_wire` / `udp_active_wire`, `tcp_active_wire_pin_remaining_ms` / `udp_active_wire_pin_remaining_ms`. Three new Prometheus metrics — `outline_ws_rust_uplink_active_wire_index{group,transport,uplink}`, `outline_ws_rust_uplink_active_wire_pin_remaining_seconds{group,transport,uplink}`, `outline_ws_rust_uplink_configured_fallbacks_count{group,uplink}` — gated on the uplink having at least one fallback configured. New Grafana panel "Active Wire (Sticky Fallback)". HTML control-plane dashboard renders a per-uplink wire chain (`primary › fallbacks[0] › fallbacks[1]`) next to the protocol pill on each uplink row, with the active wire bolded (green for primary, amber for sticky fallback) and a `⏱ Ns` countdown chip next to the active fallback while the auto-failback pin is in flight. TCP/UDP active wires render on a single combined line when they agree, on two leg-tagged lines when they diverge. Per-wire effective mode + submode + downgrade flags surfaced on the snapshot and active-pill; active-wire RTT shown in the weight cell.

- **REST control-plane CRUD for `[[outline.uplinks.fallbacks]]`**. The `/control/uplinks` endpoints (POST create, PATCH update, GET list) now accept a `fallbacks: [...]` array on the JSON payload. PATCH semantics: a present `fallbacks` array **replaces** the entire list (no per-entry merging); empty `[]` clears all fallbacks; omitting the field leaves the existing list untouched. Implementation fixes a latent bug in `table_to_section` / `table_to_json` that dropped nested `ArrayOfTables` items.

- **Drain warm-standby pool on active-wire transition off primary.** New `UplinkManager::drain_standby_pool(uplink_index, transport)` clears the deque when `active_wire` advances 0 → non-zero; both `record_wire_outcome` and probe-driven `advance_active_wire_on_probe_failure` callers spawn a tokio task to drain after detecting the transition.

- **Active-wire RTT EWMA via Prometheus + Grafana.** Snapshot exposes per-wire effective mode + submode + downgrade flags; the legacy protocol pill style is preserved on the active chip.

- **HTTP(S) proxy install** — install script now downloads release artifacts through an HTTP(S) proxy.

### Changed

- **Hysteresis stack polish.** Multiple iterations of cap-clear and downgrade gating: probe-failure downgrade chain walks past the first step rather than stopping; sticky walk-up + recovery cooldown stop H2↔configured oscillation; symmetric XHTTP recovery, walk-up, and `min_failures` descent gate; post-recovery grace renewable on each probe success with a two-success streak gate to clear the cap; post-recovery grace absorbs a single probe-fail right after recovery clear; post-recovery grace extended to silent-fallback and runtime triggers; active wire re-pins on probe failure after pin expiry.

### Fixed

- Bootstrap fallback now fires when the primary is unhealthy from the first probe instead of waiting for the first session to fail.

## [1.4.3] - 2026-05-06

### Added

- **`[outline.probe.http]` accepts a `urls = [...]` rotation list** in addition to the single `url = "..."` field. The probe advances through the list one entry per call (atomic cursor on `HttpProbeConfig`, shared across uplinks in the group), so consecutive probe calls hit consecutive endpoints. Spreading load across multiple targets surfaces per-site outages instead of masking them behind one always-reachable URL, and warm-keepalive ticks rotate through the same list. Either `url` or `urls` may be set; `urls` wins if both are present.

- **Warm-probe keepalive loop** that periodically refreshes the warm probe pipe so the optimisation that reuses a warm pipe for the HTTP / DNS probes does not silently expire under low traffic. Auto-disabled when `probe.interval_secs` is so tight that the keepalive would interfere with the regular probe cycle.

- **Reuse warm pipes across probe cycles**: a warm VLESS TCP probe pipe is reused across HTTP probe cycles, a warm VLESS UDP transport across DNS probe cycles, and the warm-probe slots are extended to Shadowsocks-over-WebSocket uplinks. The WS / UDP-WS sub-probes are skipped when a warm pipe already proves liveness on the same uplink.

- **Warm-keepalive measurements feed `latency` / `rtt_ewma`** so the scoring signal isn't frozen on uplinks where all probes are skipped.

- **Documentation reference for `[outline]` configuration shape and load balancing.** New sections in `docs/UPLINK-CONFIGURATIONS.md` (and the Russian mirror): "Top-level `[outline]` shape" — describes the inline single-uplink shorthand vs the multi-uplink + groups production shape, and the `outline.transport` enum (`ws` / `shadowsocks` / `vless`); "Load-balancing reference" — full field-by-field table for `[outline.load_balancing]` (legacy single-group surface) and the equivalent fields under `[[uplink_group]]` (multi-group surface), with defaults sourced from `src/config/load/balancing.rs` and `crates/outline-transport/src/vless/udp_mux.rs`, plus a routing-scope cheat sheet (`per_flow` / `per_uplink` / `global`) and the `mode` × `scope` interaction matrix. `config.toml` now ships a commented-out `[outline.load_balancing]` template and an inline-`[outline]` shorthand example.

- **Per-group probe overrides documentation** — `[[uplink_group]] probe.*` overrides are now documented alongside the top-level `[outline.probe]` reference.

### Changed

- **Refactor: control / uplinks_crud split by handler responsibility**; `crates/outline-transport/src/xhttp/mod.rs` split into stream + h2 carriers; `vless.rs` split into per-concern submodules; runtime types extracted from `types.rs` in `outline-uplink`; the chunk-0 / pinned-relay phases in `src/proxy/tcp/connect/` renamed from `phase1` / `phase2` to `chunk0_failover` / `pinned_relay`.

- **`install_test_tls_root` gated behind the `test-tls` feature** so production binaries never expose the test-only TLS override slot.

- **Graceful drain of control / dashboard / metrics endpoints on shutdown**, so in-flight HTTP requests are completed before the listener task exits.

- **`spawn_route_watchers` cancellable via a guard** — the route file-watchers can now be cleanly stopped on shutdown instead of leaking through process exit.

- **DnsCache bounded with approximate-LRU eviction** so long-running processes can't accumulate unbounded DNS state.

- **Removed `migrate_state_dir`** — the legacy state-directory migration helper from earlier releases is no longer needed and was removed.

- **Dashboard adds weight and selection-score columns** to the topology UI, and the RTT column now shows per-transport EWMA instead of the combined selection score.

### Fixed

- **`tcp/udp_rtt_ewma_ms` exposed on the topology endpoint**, so dashboards that joined `/control/topology` with Prometheus didn't have to round-trip through `/snapshot` for the score signal.

## [1.4.2] - 2026-05-03

### Added

- **Per-host browser fingerprint diversification for the WS / XHTTP dial paths.** WS H1 / H2 / H3 upgrades and XHTTP H1 / H2 / H3 GET / POST requests can now mix in browser-style identification headers (`User-Agent`, `Accept`, `Accept-Language`, `Accept-Encoding`, the Sec-CH-UA family, and the matching `Sec-Fetch-{Site,Mode,Dest}` triplet — `mode=websocket,dest=websocket` for WS upgrades, `mode=cors,dest=empty` for XHTTP), so passive DPI rules keying on "WS upgrade missing User-Agent" or "XHTTP POST missing browser headers" stop separating this client from real browser traffic. The pool ships six representative profiles — Chrome 130 (Windows + macOS), Firefox 130 (Windows + macOS), Safari 17 (macOS), Edge 130 (Windows) — chosen so a per-host-stable selector lands on a Chromium identity for ~⅔ of peers and a Gecko / WebKit identity for the remaining ⅓, matching rough real-world browser-share. Selection is keyed by `(host, port)` via `DefaultHasher` and sticks for the lifetime of the process. The knob is opt-in via the new top-level `fingerprint_profile` config key — accepts `"off"` / `"none"` / `"disabled"` (default — wire shape byte-identical to pre-knob builds), `"stable"` / `"per_host_stable"` / `"per-host-stable"` / `"per-host"` (one identity per host:port), or `"random"` (fresh profile per dial). Deliberately NOT covered (separate, costlier work): TLS ClientHello / JA3 / JA4; ALPN ordering; HTTP/2 SETTINGS frame fingerprint (Akamai / JA4H2); QUIC transport-parameter ordering. Documented in `docs/UPLINK-CONFIGURATIONS.md` "Browser fingerprint diversification".

- **Per-uplink override for the browser fingerprint diversification strategy.** Each `[[outline.uplinks]]` entry accepts an optional `fingerprint_profile` key with the same string aliases as the top-level knob; omitting it inherits the top-level value. Useful when one uplink must keep a byte-identical xray-style wire shape while siblings on the same `host:port` opt into per-host-stable identities — siblings can no longer flip each other's profile via the global. Plumbing rides on a new `tokio::task_local!` scope inside `outline_transport::fingerprint_profile`: `with_strategy_override(strategy, fut)` runs `fut` with `select(url)` reading `strategy` instead of the process-wide value, and the override naturally drops on `.await` completion (it does not leak into spawned post-handshake tasks like drivers or body-drain loops). The new `outline_uplink::dial::dial_in_uplink_scope(uplink, fut)` helper wraps every transport dial site that has an `UplinkConfig` in scope.

- **Inline `stream-one → packet-up` fallback for the XHTTP carrier, plus a per-host submode cache (`xhttp_submode_cache`).** When a `?mode=stream-one` dial fails on `xhttp_h2` / `xhttp_h3` after the carrier handshake succeeds, the dialer retries packet-up on the **same** TCP/TLS/h2 (or QUIC/h3) connection — no fresh handshake, just a different request shape — and records the failure in a per-host cache keyed by destination `(host, port)`. Subsequent dials to the same host skip stream-one upfront for `mode_downgrade_secs` and go straight to packet-up. The cache is the orthogonal sibling of `xhttp_mode_cache`: independent slot, TTL, and decay. Cleared early by a successful stream-one dial. The `xhttp_h1` carrier silently coerces stream-one to packet-up at `connect_xhttp` (h1 cannot multiplex a streaming GET against a streaming POST). Effective submode is published on the snapshot (`tcp_xhttp_submode` / `udp_xhttp_submode` configured + `*_block_remaining_ms`) and rendered on the dashboard's protocol pill — `stream-one` shows as `/S`, packet-up has no suffix, a live block renders as `/S↘P`.

- **`load_balancing.global_udp_strict_health`** (default `false`) — controls whether UDP probe failures and UDP cooldown gate the active uplink alongside TCP in `routing_scope = "global"`. The new lenient default treats UDP health as informational only: a TCP-healthy active uplink keeps its slot even when its UDP probe is flapping. Closes a cascade-flap mode where flaky UDP paths repeatedly demoted the active uplink: each newly-promoted backup got the same UDP probe failure on the same network path within seconds and was demoted in turn. Knob is honoured at both the top-level `[load_balancing]` block and per-`[[uplink_group]]`. No effect when `routing_scope` is `per_flow` or `per_uplink`.

- **`load_balancing.runtime_failure_window_secs`** (default 60) — time window over which `consecutive_runtime_failures` are counted toward the strict-global health-flip escalation. A new runtime failure arriving more than this window after the previous one resets the streak to 1 instead of incrementing. Set to `0` to keep the legacy behaviour. Closes a flapping mode on low-traffic strict-global uplinks where two unrelated transient errors spaced minutes apart stacked into a health flip on the active uplink and started a cascade of failovers through the whole pool.

- **Dashboard topology UI gains weight + selection-score columns**, and operators get a nag once the fingerprint pool ages past 180 days.

### Fixed

- **Global routing scope flapped between uplinks under steady noise** because `global_selection_score_latency` deliberately ignored the decayed failure penalty for *every* scenario. This is correct for `auto_failback = true` — under load the active uplink's EWMA inflates while the idle backup retains a low probe-derived EWMA, so a residual penalty would make the active look permanently worse and starve weight-driven failback. It is wrong for `auto_failback = false` (the default), where the active is sticky as long as it is healthy and the score is only consulted to pick a backup on failover or initial selection: ignoring the penalty there means failover can land on a backup that itself just failed, which then fails again. Fixed by gating penalty inclusion on `auto_failback`: with `auto_failback = false` the global selection score now uses the full `score_latency` (base EWMA + decayed `failure_penalty`); with `auto_failback = true` it stays on raw EWMA.

- **XHTTP uplink (h1 / h2 / h3) hung mid-transfer after roughly 32 messages on bulk uploads.** The `Sink` impl on `XhttpStream` reported `Poll::Ready` from `poll_ready` unconditionally and used `try_send` in `start_send`, returning `Err("xhttp outgoing buffer full")` once the per-session outbound channel filled up. The TCP / WS writer task above treats any Sink error as fatal and exits, leaving the data channel filling up against a dead consumer. Fixed by wrapping the outbound `mpsc::Sender` in `tokio_util::sync::PollSender`, which reserves a permit asynchronously and stashes the waker, so bulk uploads now apply real back-pressure. Same commit raises the in-memory burst windows for the XHTTP and WS data paths from `32 / 8 / 64` to `256` (inbound, outbound, stream-one request body, WS writer data channel) — sized for ~4 MB inflight at the 16 KB SS2022 chunk boundary. Both writer tasks now log the wire-side error before exiting instead of disappearing silently.

### Other

- `install.sh`: prune old binary backups, keep last 3.

## [1.4.1] - 2026-05-01

### Added

- **VLESS-over-XHTTP `xhttp_h1` packet-up carrier and the `xhttp_h3 → xhttp_h2 → xhttp_h1` fallback chain.** New `vless_mode = "xhttp_h1"` selects HTTP/1.1 packet-up directly; the existing `xhttp_h2` and `xhttp_h3` arms in `connect_transport` now fall through to it when the h2 dial fails (in addition to the existing `xhttp_h3 → xhttp_h2` step). The h1 carrier is the last-resort fallback for paths blocking both QUIC and h2 ALPN — wire URL stays identical (`<base>/<session>/<seq>`) so the same `xhttp_path_vless` listener serves it. Because HTTP/1.1 cannot multiplex a streaming GET against concurrent POSTs on a single connection, the driver dials **two** keep-alive sockets per session: one dedicated to the long-lived downlink GET (chunked response), and one to strictly serialised uplink POSTs (no pipelining). Throughput is bounded by single-stream POST round-trip time and is expected to lag h2 noticeably under load. Stream-one is intentionally not implemented for h1. VLESS share-link URIs accept `alpn=h1` / `alpn=http/1.1` to pin the h1 carrier directly. CLI / TOML / control-plane payloads accept `xhttp_h1` everywhere `xhttp_h2` / `xhttp_h3` are accepted.

- **Per-uplink mode-downgrade window now covers the XHTTP family.** The window guard previously only opened on `WsH3` / `Quic` failures; it now also opens on `XhttpH3` and `XhttpH2` failures, so subsequent dials skip the doomed handshake until the TTL expires (default 60 s, `mode_downgrade_secs`). Implementation switches `effective_tcp_mode` / `effective_udp_mode` from a hardcoded `WsH2` return to a family-aware ceiling tracked in the new `PerTransportStatus::mode_downgrade_capped_to` field — `WsH3` / `Quic` collapse to `WsH2`, `XhttpH3` collapses to `XhttpH2`, `XhttpH2` to `XhttpH1`. Multi-step XHTTP downgrades (`XhttpH3 → XhttpH2 → XhttpH1`) converge over consecutive dials. The cap is published through `UplinkSnapshot::tcp_mode_capped_to` / `udp_mode_capped_to`.

- **Per-host XHTTP downgrade cache (`xhttp_mode_cache`)** — sibling of the existing WS-only `ws_mode_cache`. Records `xhttp_h3` / `xhttp_h2` failures keyed by destination `(host, port)` so subsequent dials of the same upstream from different uplinks (e.g. several VLESS UUIDs behind one CDN host) skip the doomed handshake without each waiting for its own per-uplink window to fill. Each chain has its own slot — a `WsH3` failure no longer counts against an XHTTP cap and vice versa. Shares the `mode_downgrade_secs` knob with the WS cache. Cleared early by `record_success` on a meets-or-exceeds dial.

- **Test** pinning XHTTP multi-value ALPN parsing.

### Fixed

- **XHTTP packet-up uplink now puts the per-packet `seq` in the URL path (`<base>/<session>/<seq>`)** instead of the `X-Xhttp-Seq` header. This is xray / sing-box's `PlacementPath` default — the wire shape every other VLESS-XHTTP client in the wild produces. The header form was a private convention shared only with `outline-ss-rust`, which kept third-party clients (`happ`, `hiddify`, `v2rayN`) timing out against any masquerade that fronted both this client *and* a stock xray ingress: their POSTs to `<base>/<session>/<seq>` 404'd silently while ours went to `<base>/<session>` + header. Both h2 and h3 carriers send the same path shape — wire identical to vanilla xray. Server-side compatibility: `outline-ss-rust v1.4.0+` accepts both shapes (path-based wins when both are supplied); older servers (`v1.3.1` and below) only accept the header form and will need to upgrade alongside.

## [1.4.0] - 2026-04-30

### Added

- **VLESS share-link URIs as a first-class config shape.** A single `link = "vless://UUID@HOST:PORT?type=ws|xhttp|quic&...#NAME"` entry inside `[[outline.uplinks]]` (or top-level / `[outline]` inline) expands at load time into the matching `vless_id` / `vless_*_url` / `vless_mode` triple, with `transport = "vless"` implied. Recognised query parameters: `type` (`ws` / `xhttp` / `quic`), `security` (`none` / `tls` / `reality`), `path`, `alpn` (selects H1 / H2 / H3 mode variant), `mode` (`packet-up` / `stream-one`, propagated to the XHTTP dial URL), and `encryption=none`. `flow=...`, `type=tcp|grpc|h2`, divergent `sni=` / `host=`, and any non-`none` `encryption` are rejected. The same field is accepted by the CLI flag `--vless-link <URI>` (`OUTLINE_VLESS_LINK`) and the `/control/uplinks` REST endpoints (`link`, alias `share_link`). See docs/UPLINK-CONFIGURATIONS.md "VLESS share-link URIs".

- **VLESS-over-XHTTP packet-up client.** Two modes are live:
  - `vless_mode = "xhttp_h2"` — XHTTP rides a single shared TCP+TLS+h2 connection per session.
  - `vless_mode = "xhttp_h3"` — XHTTP rides QUIC + HTTP/3 (gated behind the `h3` feature). Pairs with the same outline-ss-rust listener as the h2 variant; the server's `xhttp_path_vless` route is reachable on the QUIC endpoint via the `h3` ALPN.

  Both modes generate a per-session random id used for both halves: the driver opens one long-lived GET (downlink) and pipelines POSTs (uplink) sequenced by `X-Xhttp-Seq`. The XHTTP carrier is exposed through the same `TransportStream` enum the WS variants use. New uplink config field `vless_xhttp_url` carries the base URL — required when `vless_mode` is one of the `xhttp_*` variants. Useful when WebSocket upgrades are blocked on the network path (Cloudflare-style CDN, captive-portal middleboxes).

  Three additional capabilities ride on the same dial path:
    1. **`xhttp_h3 → xhttp_h2` fallback.** When the QUIC + HTTP/3 dial fails (handshake timeout, ALPN mismatch, network-blocked UDP), the dispatcher transparently retries via h2 carrying the same `resume_request`, opens the existing `mode-downgrade` cooldown so subsequent dials skip h3 until recovery, and surfaces the originally-requested mode through `TransportStream::downgraded_from()`.
    2. **Cross-transport resumption** through the XHTTP carrier. The dial advertises `X-Outline-Resume-Capable: 1` and (when present) `X-Outline-Resume: <hex>`, then waits synchronously for the response headers so the server-issued `X-Outline-Session` is captured before the body drain starts.
    3. **Stream-one carrier** selected purely from the dial URL. Writing `?mode=stream-one` in `vless_xhttp_url` swaps the GET+POST pair for a single bidirectional POST whose request body is the uplink and whose response body is the downlink. No new config field, no new mode variant — `XhttpSubmode::from_url(&Url)` reads the query at dial time. On h3 the stream is split via `RequestStream::split` so uplink and downlink halves run on dedicated tasks.

- **`outline_transport::install_test_tls_root(CertificateDer)`** — test-only knob that pins a custom self-signed root for the XHTTP h2 / h3 dial paths. The override slot is a `RwLock<Option<…>>` defaulting to `None`, so production callers keep the existing webpki behaviour with one extra read per dial. The motivating consumer is the cross-repo end-to-end test in `outline-ss-rust`, which spins up an in-process self-signed server and dials it through the regular `connect_transport` entry.

### Changed

- **Breaking config / CLI / API rename.** The transport-mode fields are now `tcp_mode` / `udp_mode` / `vless_mode` everywhere — TOML config (`tcp_mode = "h2"`), CLI (`--tcp-mode`, `--udp-mode`, `--vless-mode`), env vars (`OUTLINE_TCP_MODE`, `OUTLINE_UDP_MODE`, `OUTLINE_VLESS_MODE`), control-plane JSON (`/control/topology`, `/control/uplinks`), dashboard payload, and Rust API (`UplinkConfig::tcp_mode`, `effective_tcp_mode()`). Old `*_ws_mode` names are removed without aliases — existing TOML files and scripts must be renamed by hand. Reason: with `xhttp_h2` / `xhttp_h3` / `quic` no longer riding only WebSocket, the `_ws_` infix had become misleading.

- **Test-mode bypass for the process-wide QUIC endpoint caches.** When the test override is set (i.e. `install_test_tls_root` has been called), `H3_CLIENT_ENDPOINT_V4` / `_V6` and the raw-QUIC `QUIC_CLIENT_ENDPOINT_V4` / `_V6` skip the cache and bind a fresh endpoint per dial. Each `#[tokio::test]` runs in its own runtime; the cached endpoint's driver task is bound to whichever runtime first hit the cache, so it dies the moment that test ends and the next test sees `endpoint driver future was dropped`. Production behaviour is unchanged.

- **Dashboard panel now correctly renders `xhttp_h3` → `xhttp_h2` downgrades** (previously the H3/QUIC downgrade decoration only fired on the legacy short-form mode strings, leaving xhttp uplinks visually frozen on the configured mode). VLESS uplinks now publish `tcp_mode` / `udp_mode` for `xhttp_h2` / `xhttp_h3` modes too — previously the field was emitted only when `vless_ws_url` was set, so XHTTP-only uplinks fell back to the default rendering ("VLESS/WS/H1").

### Fixed

- **WebSocket-over-h2 dialer was sending `:path = //{ws_path}`** because `H2Dialer::open_on` formatted `target_uri` as `format!("{scheme}://{auth}/{path}")` while `websocket_path` already returns a leading `/`. Server-side axum routers reject the doubled slash with 404, which the WS-h2 dispatcher silently masked for years by falling back to h1 (tungstenite's URL handler normalises the slash on its way to the wire). The h2 path now concatenates without re-adding the slash. Visible only on h2-only servers (RFC 8441 stacks that don't speak h1) and surfaced by the cross-repo h3→h2 fallback test in `outline-ss-rust`.

- **XHTTP h3 stream-one closed the QUIC connection with `H3_NO_ERROR`** before any application bytes flowed: the only `SendRequest` was being moved into `open_h3_stream_one`, which dropped it on return, and the h3 crate's `SendRequest::drop` triggers a graceful close once `sender_count` hits zero. Mirrored the packet-up pattern — clone before the open helper, hold the clone alive in the driver task. Same commit moves the quinn `Endpoint` into the driver task (the previous `let _endpoint_guard = endpoint;` only kept it alive for the function body, not the session lifetime).

- **Dashboard Uplinks editor now exposes the full XHTTP triple** (`vless_xhttp_url`, `vless_mode`, `vless_id`) so XHTTP uplinks can be created and edited from the UI without hitting `unknown field` 400s.

- **VLESS probes / standby refill route through the same `vless_dial_url()` helper as the live data path**, so probes that pick the XHTTP carrier no longer fall back to `vless_ws_url` when only `vless_xhttp_url` is configured.

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
