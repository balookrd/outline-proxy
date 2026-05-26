use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use url::Url;

use outline_transport::{ServerAddr, TransportMode};
use outline_uplink::{LoadBalancingMode, RoutingScope, UplinkTransport};
use shadowsocks_crypto::CipherKind;

#[derive(Debug, Deserialize)]
pub(crate) struct ConfigFile {
    pub(super) socks5: Option<Socks5Section>,
    pub(super) transport: Option<UplinkTransport>,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_mode: Option<TransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_mode: Option<TransportMode>,
    pub(super) vless_ws_url: Option<Url>,
    /// Base URL for VLESS-over-XHTTP packet-up. The session id is
    /// appended at dial time (one path segment after the base path).
    /// Required when `vless_mode` is `xhttp_h1` / `xhttp_h2` / `xhttp_h3`.
    pub(super) vless_xhttp_url: Option<Url>,
    pub(super) vless_mode: Option<TransportMode>,
    /// VLESS share-link URI (`vless://UUID@HOST:PORT?...#NAME`). When set,
    /// expands at load time into the matching `vless_id`, dial URL and
    /// `vless_mode`. Mutually exclusive with explicitly-set `vless_*`
    /// fields. See docs/UPLINK-CONFIGURATIONS.md "VLESS share-link URIs".
    pub(super) link: Option<String>,
    pub(super) tcp_addr: Option<ServerAddr>,
    pub(super) udp_addr: Option<ServerAddr>,
    pub(super) method: Option<CipherKind>,
    pub(super) password: Option<String>,
    pub(super) fwmark: Option<u32>,
    pub(super) ipv6_first: Option<bool>,
    pub(super) uplinks: Option<Vec<UplinkSection>>,
    pub(super) probe: Option<ProbeSection>,
    pub(super) load_balancing: Option<LoadBalancingSection>,
    pub(super) outline: Option<OutlineSection>,
    pub(super) metrics: Option<MetricsSection>,
    pub(super) control: Option<ControlSection>,
    pub(super) dashboard: Option<DashboardSection>,
    #[cfg(feature = "tun")]
    pub(super) tun: Option<TunSection>,
    pub(super) h2: Option<H2Section>,
    pub(super) udp_recv_buf_bytes: Option<usize>,
    pub(super) udp_send_buf_bytes: Option<usize>,
    /// SO_MARK for direct-route sockets. Linux only.
    pub(super) direct_fwmark: Option<u32>,
    /// Explicit uplink groups with per-group LB + probe config.
    pub(super) uplink_group: Option<Vec<UplinkGroupSection>>,
    /// Policy routes mapping CIDR prefixes to groups or `direct`/`drop`.
    pub(super) route: Option<Vec<RouteSection>>,
    /// Override the path where active-uplink state is persisted.
    /// Defaults to the config file path with extension replaced by
    /// `.state.toml` (e.g. `config.toml` → `config.state.toml`).
    /// Set to a writable location when the config directory is read-only
    /// (e.g. `/var/lib/outline-ws/state.toml`).
    pub(super) state_path: Option<PathBuf>,
    /// TCP session timeouts applied to SOCKS CONNECT and direct sessions.
    /// All fields optional; unset ones inherit compile-time defaults.
    pub(super) tcp_timeouts: Option<TcpTimeoutsSection>,
    /// Browser fingerprint diversification strategy applied to WS / XHTTP
    /// dials. Accepts `"off"` / `"none"` / `"disabled"` (default — wire
    /// shape unchanged), `"stable"` / `"per_host_stable"` /
    /// `"per-host-stable"` / `"per-host"` (one identity per
    /// `(host, port)` for the lifetime of the process), or `"random"`
    /// (fresh profile per dial). See docs for the trade-offs.
    pub(super) fingerprint_profile: Option<outline_transport::FingerprintProfileStrategy>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TcpTimeoutsSection {
    pub(super) post_client_eof_downstream_secs: Option<u64>,
    pub(super) upstream_response_secs: Option<u64>,
    pub(super) socks_upstream_idle_secs: Option<u64>,
    pub(super) direct_idle_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Socks5Section {
    pub(super) listen: Option<SocketAddr>,
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
    pub(super) users: Option<Vec<Socks5UserSection>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Socks5UserSection {
    pub(super) username: Option<String>,
    pub(super) password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OutlineSection {
    pub(super) transport: Option<UplinkTransport>,
    pub(super) tcp_ws_url: Option<Url>,
    pub(super) tcp_mode: Option<TransportMode>,
    pub(super) udp_ws_url: Option<Url>,
    pub(super) udp_mode: Option<TransportMode>,
    pub(super) vless_ws_url: Option<Url>,
    /// Base URL for VLESS-over-XHTTP packet-up. The session id is
    /// appended at dial time (one path segment after the base path).
    /// Required when `vless_mode` is `xhttp_h1` / `xhttp_h2` / `xhttp_h3`.
    pub(super) vless_xhttp_url: Option<Url>,
    pub(super) vless_mode: Option<TransportMode>,
    /// VLESS share-link URI. Same semantics as `ConfigFile::link`; provided
    /// here so the inline-uplink shape can carry a one-line VLESS config.
    pub(super) link: Option<String>,
    pub(super) tcp_addr: Option<ServerAddr>,
    pub(super) udp_addr: Option<ServerAddr>,
    pub(super) method: Option<CipherKind>,
    pub(super) password: Option<String>,
    pub(super) fwmark: Option<u32>,
    pub(super) ipv6_first: Option<bool>,
    pub(super) uplinks: Option<Vec<UplinkSection>>,
    pub(super) probe: Option<ProbeSection>,
    pub(super) load_balancing: Option<LoadBalancingSection>,
}

#[derive(Debug, Deserialize)]
pub(super) struct MetricsSection {
    pub(super) listen: Option<SocketAddr>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ControlSection {
    pub(super) listen: Option<SocketAddr>,
    pub(super) token: Option<String>,
    pub(super) token_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub(super) struct DashboardSection {
    /// Presence of [dashboard] enables the dashboard by default. Set
    /// `enabled = false` to keep the config block around without binding.
    pub(super) enabled: Option<bool>,
    pub(super) listen: Option<SocketAddr>,
    pub(super) refresh_interval_secs: Option<u64>,
    pub(super) request_timeout_secs: Option<u64>,
    pub(super) instances: Option<Vec<DashboardInstanceSection>>,
}

#[derive(Debug, Deserialize)]
pub(super) struct DashboardInstanceSection {
    pub(super) name: Option<String>,
    pub(super) control_url: Option<Url>,
    pub(super) token: Option<String>,
    pub(super) token_file: Option<PathBuf>,
}

#[cfg(feature = "tun")]
#[derive(Debug, Deserialize)]
pub(super) struct TunSection {
    pub(super) path: Option<PathBuf>,
    pub(super) name: Option<String>,
    pub(super) mtu: Option<usize>,
    pub(super) max_flows: Option<usize>,
    pub(super) idle_timeout_secs: Option<u64>,
    pub(super) tcp: Option<TunTcpSection>,
    pub(super) defrag_max_fragment_sets: Option<usize>,
    pub(super) defrag_max_fragments_per_set: Option<usize>,
    pub(super) defrag_max_total_bytes: Option<usize>,
    pub(super) defrag_max_bytes_per_set: Option<usize>,
    /// Built-in bypass for IKE / IPsec NAT-T traffic (UDP/500, UDP/4500).
    /// When `true`, those flows skip policy routing and use the direct path
    /// (same as `via = "direct"`), which lets VoWiFi / IKEv2 clients work
    /// without ESP transit through the proxy. Default `false`.
    pub(super) ipsec_bypass: Option<bool>,
    /// Whether the TUN UDP path may emit ICMP PTBs advertising a path
    /// MTU below QUIC v1's Initial-datagram minimum (1200 v4 / 1280 v6).
    /// Default `false` — sub-minimum PTBs would push compliant QUIC
    /// clients onto a TCP fallback. Set `true` to restore unconditional
    /// emission for VoWiFi / IKE-only setups. See `docs/TUN-PMTUD.md`.
    pub(super) pmtud_emit_below_quic_initial: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(super) struct H2Section {
    pub(super) initial_stream_window_size: Option<u32>,
    pub(super) initial_connection_window_size: Option<u32>,
}

#[cfg(feature = "tun")]
#[derive(Debug, Deserialize)]
pub(super) struct TunTcpSection {
    pub(super) connect_timeout_secs: Option<u64>,
    pub(super) handshake_timeout_secs: Option<u64>,
    pub(super) half_close_timeout_secs: Option<u64>,
    pub(super) max_pending_server_bytes: Option<usize>,
    pub(super) backlog_abort_grace_secs: Option<u64>,
    pub(super) backlog_hard_limit_multiplier: Option<usize>,
    pub(super) backlog_no_progress_abort_secs: Option<u64>,
    pub(super) max_buffered_client_segments: Option<usize>,
    pub(super) max_buffered_client_bytes: Option<usize>,
    pub(super) max_retransmits: Option<u32>,
    pub(super) keepalive_idle_secs: Option<u64>,
    pub(super) keepalive_interval_secs: Option<u64>,
    pub(super) keepalive_max_probes: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct UplinkSection {
    pub(crate) name: Option<String>,
    pub(crate) transport: Option<UplinkTransport>,
    pub(crate) tcp_ws_url: Option<Url>,
    pub(crate) tcp_mode: Option<TransportMode>,
    pub(crate) udp_ws_url: Option<Url>,
    pub(crate) udp_mode: Option<TransportMode>,
    pub(crate) vless_ws_url: Option<Url>,
    /// Base URL for VLESS-over-XHTTP packet-up. See top-level field
    /// of the same name on `ConfigFile` for semantics.
    pub(crate) vless_xhttp_url: Option<Url>,
    pub(crate) vless_mode: Option<TransportMode>,
    /// VLESS share-link URI (`vless://UUID@HOST:PORT?...#NAME`). When set,
    /// expands at load time into the matching `vless_id`, dial URL and
    /// `vless_mode`. Mutually exclusive with explicitly-set `vless_*`
    /// fields. See docs/UPLINK-CONFIGURATIONS.md "VLESS share-link URIs".
    pub(crate) link: Option<String>,
    pub(crate) tcp_addr: Option<ServerAddr>,
    pub(crate) udp_addr: Option<ServerAddr>,
    pub(crate) method: Option<CipherKind>,
    pub(crate) password: Option<String>,
    pub(crate) weight: Option<f64>,
    pub(crate) fwmark: Option<u32>,
    pub(crate) ipv6_first: Option<bool>,
    /// VLESS user id (hex/dashed), required when `transport = "vless"`.
    pub(crate) vless_id: Option<String>,
    /// New: group this uplink belongs to. Required when `[[uplink_group]]` is
    /// declared; optional in legacy config (all uplinks land in `default`).
    pub(crate) group: Option<String>,
    /// Per-uplink override for the browser fingerprint diversification
    /// strategy. Same accepted aliases as the top-level
    /// `fingerprint_profile` key (`"off"`, `"stable"`, `"random"`, …);
    /// omitted means inherit the top-level value. Useful for an uplink
    /// that must keep a byte-identical xray-style wire shape while
    /// siblings on the same `host:port` opt into per-host-stable.
    pub(crate) fingerprint_profile: Option<outline_transport::FingerprintProfileStrategy>,
    /// Optional list of fallback transports tried when the primary
    /// transport on this uplink fails to dial / chunk-0 in a single
    /// session. Each entry carries its own wire-shape fields; identity
    /// (name / weight / group) stays with the parent uplink. See
    /// [`FallbackSection`] for the accepted fields and
    /// `docs/UPLINK-CONFIGURATIONS.md` for the rationale.
    pub(crate) fallbacks: Option<Vec<FallbackSection>>,
    /// Random forward-only wire rotation. When `true`:
    ///   * the wire chain `[primary, fallbacks[0], fallbacks[1], …]` is
    ///     reshuffled once at config load (every process restart picks a
    ///     different ordering — primary may end up at any position),
    ///   * the active-wire state machine still advances forward through
    ///     the chain on consecutive dial failures (wrapping at the end),
    ///   * once the active wire has advanced through **every** wire of
    ///     the chain without a single successful dial in between, the
    ///     uplink is reported as runtime-failed on that transport so the
    ///     load balancer fails over to another uplink,
    ///   * any successful wire dial clears the "round" counter — traffic
    ///     stabilising on any wire restarts the round, and rotation
    ///     continues forward from the wire that just worked on the next
    ///     failure.
    /// Default `false` preserves the legacy operator-ordered chain and
    /// the existing sticky / wrap-forever wire state machine.
    pub(crate) shuffle_wires: Option<bool>,
    /// Per-wire carrier-downgrade switch. When omitted or `true`, the
    /// proxy keeps the legacy `h3 → h2 → h1` (and `xhttp_h3 →
    /// xhttp_h2 → xhttp_h1`) descent inside each WS / VLESS-XHTTP wire:
    /// after a carrier failure the wire is capped one rank lower for
    /// `mode_downgrade_secs`, and only when it has reached the family's
    /// floor (`ws_h1` / `xhttp_h1`) does the next failure roll over to
    /// the next wire (under `shuffle_wires`) or the next uplink.
    ///
    /// Set to `false` to skip the vertical cascade entirely on this
    /// uplink: `extend_mode_downgrade` is a no-op, no `mode_downgrade_*`
    /// state ever installs, and `wire_is_at_carrier_floor` reports
    /// every wire as "at floor" — failures move straight to the next
    /// wire (with `shuffle_wires = true`) or trigger the same legacy
    /// `record_wire_outcome` advance (without `shuffle_wires`). Useful
    /// when an operator knows the intermediate carriers (h2, h1) are
    /// also useless on the same wire — e.g. DPI drops the whole
    /// upstream regardless of HTTP version — so spending one
    /// `mode_downgrade_secs` window per rank before rotating is pure
    /// latency and wasted dial attempts.
    pub(crate) carrier_downgrade: Option<bool>,
    /// Periodic active-wire reroll interval. Accepts human-readable
    /// duration strings: `"30s"`, `"5m"`, `"1h"`, `"1h30m"`, `"2d"`.
    /// When set, a background tokio task rerolls `active_wire` on TCP
    /// and UDP independently every interval to a random wire of the
    /// chain — picked collision-free against the other rotated uplinks
    /// in the same group on the same tick where possible. Per-wire
    /// failure counters (`active_wire_streak`,
    /// `wires_failed_in_round`, `consecutive_failures`,
    /// `consecutive_runtime_failures`) and any active downgrade-window
    /// pin are reset so the new wire starts with a clean budget.
    ///
    /// Useful as a defence against time-based DPI heuristics: even an
    /// uplink that has been working steadily on one wire will pivot
    /// to a fresh wire on every tick, refusing to look like a
    /// long-lived stable flow on any specific carrier shape.
    /// Independent of `shuffle_wires` (which only controls the
    /// initial chain order at config load) — the two can be combined
    /// or set independently.
    pub(crate) shuffle_timer: Option<String>,
}

/// One `[[outline.uplinks.fallbacks]]` entry. Mirrors the wire-shape
/// subset of [`UplinkSection`] — no `name` / `weight` / `group` / `link`
/// (those are parent-level) and `transport` is required (no implicit
/// default; the whole point of a fallback is to switch the wire family).
/// `cipher` / `password` / `fwmark` / `ipv6_first` / `fingerprint_profile`
/// are optional and inherited from the parent uplink at validation time.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct FallbackSection {
    pub(crate) transport: UplinkTransport,
    pub(crate) tcp_ws_url: Option<Url>,
    pub(crate) tcp_mode: Option<TransportMode>,
    pub(crate) udp_ws_url: Option<Url>,
    pub(crate) udp_mode: Option<TransportMode>,
    pub(crate) vless_ws_url: Option<Url>,
    pub(crate) vless_xhttp_url: Option<Url>,
    pub(crate) vless_mode: Option<TransportMode>,
    pub(crate) tcp_addr: Option<ServerAddr>,
    pub(crate) udp_addr: Option<ServerAddr>,
    pub(crate) method: Option<CipherKind>,
    pub(crate) password: Option<String>,
    pub(crate) fwmark: Option<u32>,
    pub(crate) ipv6_first: Option<bool>,
    pub(crate) vless_id: Option<String>,
    pub(crate) fingerprint_profile: Option<outline_transport::FingerprintProfileStrategy>,
}

/// New: explicit uplink group with its own LB config and probe override.
///
/// Top-level `[probe]` acts as a template; unspecified fields in
/// `[uplink_group.probe]` are inherited from it.
#[derive(Debug, Deserialize, Clone)]
pub(super) struct UplinkGroupSection {
    pub(super) name: Option<String>,
    pub(super) mode: Option<LoadBalancingMode>,
    pub(super) routing_scope: Option<RoutingScope>,
    pub(super) sticky_ttl_secs: Option<u64>,
    pub(super) hysteresis_ms: Option<u64>,
    pub(super) failure_cooldown_secs: Option<u64>,
    pub(super) tcp_chunk0_failover_timeout_secs: Option<u64>,
    pub(super) warm_standby_tcp: Option<usize>,
    pub(super) warm_standby_udp: Option<usize>,
    pub(super) rtt_ewma_alpha: Option<f64>,
    pub(super) failure_penalty_ms: Option<u64>,
    pub(super) failure_penalty_max_ms: Option<u64>,
    pub(super) failure_penalty_halflife_secs: Option<u64>,
    /// Cooldown before retrying the configured "advanced" dial mode (H3 or
    /// raw QUIC) after a failure forced a fall-back to H2. The legacy
    /// alias `h3_downgrade_secs` (from when the cooldown only covered
    /// H3 → H2) is still accepted. Default: 60.
    #[serde(alias = "h3_downgrade_secs")]
    pub(super) mode_downgrade_secs: Option<u64>,
    /// Window over which consecutive runtime (data-plane) failures are
    /// counted toward the health-flip escalation. A new failure arriving
    /// later than this window after the previous one resets the streak to
    /// 1 instead of incrementing. `0` disables decay (legacy behaviour).
    /// Default: 60.
    pub(super) runtime_failure_window_secs: Option<u64>,
    /// Window over which consecutive **chunk-0 timeouts** on a single
    /// uplink/transport are counted toward the same `probe.min_failures`
    /// health-flip escalation. Independent of `runtime_failure_window` and
    /// typically much wider so sparse chunk-0 timeouts (silent upstream
    /// pattern) still accumulate and trigger an active-uplink switch.
    /// `0` disables the dedicated counter. Default: 300 (5 min).
    pub(super) chunk0_failure_window_secs: Option<u64>,
    /// In `routing_scope = "global"`, gate the active uplink on UDP health
    /// alongside TCP health. Default: `false` — UDP failures are
    /// informational and do not kick the active. `true` restores pre-1.4.x
    /// strict behaviour.
    pub(super) global_udp_strict_health: Option<bool>,
    pub(super) udp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_standby_keepalive_secs: Option<u64>,
    pub(super) tcp_active_keepalive_secs: Option<u64>,
    pub(super) warm_probe_keepalive_secs: Option<u64>,
    pub(super) auto_failback: Option<bool>,
    pub(super) vless_udp_max_sessions: Option<usize>,
    pub(super) vless_udp_session_idle_secs: Option<u64>,
    pub(super) vless_udp_janitor_interval_secs: Option<u64>,
    /// Maximum bytes of recently-sent uplink payload kept buffered for
    /// the Ack-Prefix Protocol mid-session retry path. On a mid-session
    /// transport reset the client re-dials with the capability bit, the
    /// server reports its `up_acked` offset on the new stream's first
    /// SS-AEAD chunk, and the client replays the buffered tail from
    /// that offset. `0` disables retry (and stops buffering). Default:
    /// 256 KiB. See `docs/UPLINK-CONFIGURATIONS.md` for guidance.
    pub(super) tcp_mid_session_retry_buffer_bytes: Option<usize>,
    /// Maximum number of mid-session redial attempts per pinned SOCKS
    /// TCP session. `0` disables retry entirely (equivalent to
    /// `tcp_mid_session_retry_buffer_bytes = 0`); higher values
    /// allow successive redials when each previous one also fails.
    /// Default: `1`.
    pub(super) tcp_mid_session_retry_budget: Option<u8>,
    /// Behaviour on a chunk larger than the mid-session retry
    /// buffer cap. `"soft"` (default) keeps the session alive and
    /// surfaces `failed_replay` on future retries; `"hard"` drops
    /// the session immediately to guarantee retryability for the
    /// rest. See the same-named field on `LoadBalancingConfig` for
    /// full semantics.
    pub(super) tcp_mid_session_retry_overflow_policy: Option<outline_uplink::OverflowPolicy>,
    /// Hard upper bound on how long the orchestrator waits for the
    /// v1 Ack-Prefix control frame on a successful resume hit.
    /// Default: 5 seconds. See the same-named field on
    /// `LoadBalancingConfig` for full semantics.
    pub(super) tcp_mid_session_retry_consume_timeout_secs: Option<u64>,
    /// Per-group override of `tcp_symmetric_replay_enabled`. Default
    /// inherits the top-level value (`true`).
    pub(super) tcp_symmetric_replay_enabled: Option<bool>,
    /// Per-group override of `tcp_symmetric_replay_max_bytes`. Default
    /// inherits the top-level value (`1_048_576`).
    pub(super) tcp_symmetric_replay_max_bytes: Option<usize>,
    /// Per-group override of top-level `[probe]`; unspecified fields inherit.
    pub(super) probe: Option<ProbeSection>,
}

/// New: policy routing rule.
///
/// Exactly one of `default = true` or non-empty `prefixes`/`file`/`files`
/// must be set.
/// `via` picks the target: either a group name or the reserved `"direct"`.
/// At most one of `fallback_via` / `fallback_direct` / `fallback_drop` is allowed.
///
/// Prefix sources are merged: inline `prefixes`, a single `file`, and any
/// additional paths in `files` all contribute to the same CIDR set.
#[derive(Debug, Deserialize, Clone)]
pub(super) struct RouteSection {
    pub(super) prefixes: Option<Vec<String>>,
    pub(super) file: Option<PathBuf>,
    pub(super) files: Option<Vec<PathBuf>>,
    pub(super) file_poll_secs: Option<u64>,
    pub(super) default: Option<bool>,
    pub(super) via: Option<String>,
    pub(super) fallback_via: Option<String>,
    pub(super) fallback_direct: Option<bool>,
    pub(super) fallback_drop: Option<bool>,
    /// If true, the rule matches addresses NOT in the prefix list.
    /// Useful for "tunnel only listed prefixes, everything else goes direct".
    pub(super) invert: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct ProbeSection {
    pub(super) interval_secs: Option<u64>,
    pub(super) timeout_secs: Option<u64>,
    pub(super) max_concurrent: Option<usize>,
    pub(super) max_dials: Option<usize>,
    pub(super) min_failures: Option<usize>,
    pub(super) attempts: Option<usize>,
    pub(super) ws: Option<WsProbeSection>,
    pub(super) http: Option<HttpProbeSection>,
    pub(super) dns: Option<DnsProbeSection>,
    pub(super) tcp: Option<TcpProbeSection>,
    pub(super) tls: Option<TlsProbeSection>,
    /// When false, disables the "skip probe when uplink already carries
    /// healthy traffic" optimisation. Default true (skip enabled).
    pub(super) skip_when_active: Option<bool>,
    /// Liveness-probe interval in seconds. Even when the activity-based
    /// skip would otherwise hold, force a probe cycle to run after this
    /// many seconds without one. `0` disables the override; defaults to
    /// 300 (5 minutes).
    pub(super) liveness_interval_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct WsProbeSection {
    pub(super) enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct HttpProbeSection {
    /// Single URL form (legacy / convenience). Either `url` or `urls` must
    /// be set; if both are set, `urls` wins.
    pub(super) url: Option<Url>,
    /// Rotation list. The probe advances through this list one entry per
    /// cycle so each cycle hits a different endpoint, surfacing per-site
    /// outages and spreading load.
    pub(super) urls: Option<Vec<Url>>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct DnsProbeSection {
    pub(super) server: String,
    pub(super) port: Option<u16>,
    pub(super) name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct TcpProbeSection {
    pub(super) host: String,
    pub(super) port: Option<u16>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct TlsProbeSection {
    /// Single target form (legacy / convenience). Either `target` or
    /// `targets` must be set; if both are set, `targets` wins.
    /// Accepts `"host:port"` or just `"host"` (port defaults to 443).
    pub(super) target: Option<String>,
    /// Rotation list. Each entry is `"host:port"` (or `"host"` for port 443);
    /// the probe advances through the list one entry per cycle, surfacing
    /// per-SNI filtering instead of masking it behind one still-reachable target.
    pub(super) targets: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct LoadBalancingSection {
    pub(super) mode: Option<LoadBalancingMode>,
    pub(super) routing_scope: Option<RoutingScope>,
    pub(super) sticky_ttl_secs: Option<u64>,
    pub(super) hysteresis_ms: Option<u64>,
    pub(super) failure_cooldown_secs: Option<u64>,
    pub(super) tcp_chunk0_failover_timeout_secs: Option<u64>,
    pub(super) warm_standby_tcp: Option<usize>,
    pub(super) warm_standby_udp: Option<usize>,
    pub(super) rtt_ewma_alpha: Option<f64>,
    pub(super) failure_penalty_ms: Option<u64>,
    pub(super) failure_penalty_max_ms: Option<u64>,
    pub(super) failure_penalty_halflife_secs: Option<u64>,
    /// Cooldown before retrying the configured "advanced" dial mode (H3 or
    /// raw QUIC) after a failure forced a fall-back to H2. The legacy
    /// alias `h3_downgrade_secs` (from when the cooldown only covered
    /// H3 → H2) is still accepted. Default: 60.
    #[serde(alias = "h3_downgrade_secs")]
    pub(super) mode_downgrade_secs: Option<u64>,
    /// Window over which consecutive runtime (data-plane) failures are
    /// counted toward the health-flip escalation. A new failure arriving
    /// later than this window after the previous one resets the streak to
    /// 1 instead of incrementing. `0` disables decay (legacy behaviour).
    /// Default: 60.
    pub(super) runtime_failure_window_secs: Option<u64>,
    /// Window over which consecutive **chunk-0 timeouts** on a single
    /// uplink/transport are counted toward the same `probe.min_failures`
    /// health-flip escalation. Independent of `runtime_failure_window` and
    /// typically much wider so sparse chunk-0 timeouts (silent upstream
    /// pattern) still accumulate and trigger an active-uplink switch.
    /// `0` disables the dedicated counter. Default: 300 (5 min).
    pub(super) chunk0_failure_window_secs: Option<u64>,
    /// In `routing_scope = "global"`, gate the active uplink on UDP health
    /// alongside TCP health. Default: `false` — UDP failures are
    /// informational and do not kick the active. `true` restores pre-1.4.x
    /// strict behaviour.
    pub(super) global_udp_strict_health: Option<bool>,
    pub(super) udp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_keepalive_secs: Option<u64>,
    pub(super) tcp_ws_standby_keepalive_secs: Option<u64>,
    pub(super) tcp_active_keepalive_secs: Option<u64>,
    pub(super) warm_probe_keepalive_secs: Option<u64>,
    pub(super) auto_failback: Option<bool>,
    pub(super) vless_udp_max_sessions: Option<usize>,
    pub(super) vless_udp_session_idle_secs: Option<u64>,
    pub(super) vless_udp_janitor_interval_secs: Option<u64>,
    /// Mid-session retry buffer cap (bytes). See the same-named field on
    /// `UplinkGroupSection` for full semantics; this top-level entry is
    /// the global default applied to every group that does not override
    /// it. Default: 256 KiB. `0` disables retry and the buffer.
    pub(super) tcp_mid_session_retry_buffer_bytes: Option<usize>,
    /// Mid-session retry budget per session. See the same-named field
    /// on `UplinkGroupSection` for full semantics. Default: `1`.
    pub(super) tcp_mid_session_retry_budget: Option<u8>,
    /// Mid-session retry overflow policy (`"soft"` / `"hard"`). See
    /// the same-named field on `UplinkGroupSection` for full
    /// semantics. Default: `"soft"`.
    pub(super) tcp_mid_session_retry_overflow_policy: Option<outline_uplink::OverflowPolicy>,
    /// Hard upper bound on how long the orchestrator waits for the
    /// v1 Ack-Prefix control frame on a successful resume hit. See
    /// the same-named field on `UplinkGroupSection` for full
    /// semantics. Default: `5`.
    pub(super) tcp_mid_session_retry_consume_timeout_secs: Option<u64>,
    /// Whether to opt into the v2 Symmetric Downlink Replay protocol
    /// on mid-session retry redials. Default: `true`. Setting `false`
    /// suppresses the v2 advertise without disabling v1.x retry. See
    /// `docs/SESSION-RESUMPTION.md` (server repo) § Symmetric
    /// Downlink Replay (v2).
    pub(super) tcp_symmetric_replay_enabled: Option<bool>,
    /// Hard cap on the v2 `replay_len` the client will accept from
    /// the server. Default: `1_048_576` (1 MiB). Replies above this
    /// drop the session — protection against a malicious server
    /// inducing unbounded memory pressure on the client.
    pub(super) tcp_symmetric_replay_max_bytes: Option<usize>,
}
