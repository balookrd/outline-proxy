use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow};
use serde::Deserialize;
use url::Url;

pub use outline_transport::{ServerAddr, TransportMode, VlessUdpMuxLimits};
pub use shadowsocks_crypto::CipherKind;
pub use socks5_proto::TargetAddr;

// ── UplinkTransport ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UplinkTransport {
    #[default]
    #[serde(alias = "websocket")]
    Ws,
    Shadowsocks,
    /// VLESS over WebSocket (iteration 1: TCP + UDP, no Mux, no flow/xtls,
    /// TLS supplied by the WS URL scheme `wss://` going through rustls).
    Vless,
}

impl std::str::FromStr for UplinkTransport {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ws" | "websocket" => Ok(Self::Ws),
            "shadowsocks" => Ok(Self::Shadowsocks),
            "vless" => Ok(Self::Vless),
            _ => anyhow::bail!("unsupported uplink transport: {s}"),
        }
    }
}

impl std::fmt::Display for UplinkTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ws => "ws",
            Self::Shadowsocks => "shadowsocks",
            Self::Vless => "vless",
        })
    }
}

// ── UplinkGroupConfig ────────────────────────────────────────────────────────

/// A named collection of uplinks sharing a single LB + probe configuration.
#[derive(Debug, Clone)]
pub struct UplinkGroupConfig {
    pub name: String,
    pub uplinks: Vec<UplinkConfig>,
    pub probe: ProbeConfig,
    pub load_balancing: LoadBalancingConfig,
}

// ── FallbackTransport ────────────────────────────────────────────────────────

/// Wire-level configuration for a single fallback transport on an uplink.
///
/// An [`UplinkConfig`] may list zero or more fallbacks via [`UplinkConfig::fallbacks`].
/// Each fallback represents an alternate `(transport, wire-fields)` shape that the
/// dial loop tries when the parent uplink's primary transport fails on this
/// session. Fallbacks share the parent's identity (`name`, `weight`, `group`)
/// and are not separate uplinks from the load-balancer's point of view.
///
/// `cipher` / `password` / `fwmark` / `ipv6_first` / `fingerprint_profile` are
/// inherited from the parent uplink when omitted; the loader fills them in
/// during validation. `vless_id` is mandatory for `transport = "vless"` and is
/// **not** inherited from the parent (different VLESS endpoints use different
/// uuids by definition).
///
/// Runtime-state tracking (RTT EWMA, penalty, cooldown, mode-downgrade) is
/// still attached to the parent uplink's primary transport — fallback wires
/// share the parent's scoring state. Probe-time validation of fallback wires
/// is wired through `UplinkConfig::wire_view` + the manager's per-wire probe
/// walk, so `last_any_wire_success` and `*_health_effective` reflect a
/// working fallback even on a passive uplink with no client traffic.
#[derive(Debug, Clone)]
pub struct FallbackTransport {
    pub transport: UplinkTransport,
    pub tcp_ws_url: Option<Url>,
    pub tcp_mode: TransportMode,
    pub udp_ws_url: Option<Url>,
    pub udp_mode: TransportMode,
    pub vless_ws_url: Option<Url>,
    pub vless_xhttp_url: Option<Url>,
    pub vless_mode: TransportMode,
    pub vless_id: Option<[u8; 16]>,
    pub tcp_addr: Option<ServerAddr>,
    pub udp_addr: Option<ServerAddr>,
    pub cipher: CipherKind,
    pub password: String,
    pub fwmark: Option<u32>,
    pub ipv6_first: bool,
    pub fingerprint_profile: Option<outline_transport::FingerprintProfileStrategy>,
}

impl FallbackTransport {
    /// True when this fallback is configured for UDP-style sessions.
    /// Mirrors [`UplinkConfig::supports_udp`] but operates on the
    /// fallback's own wire fields.
    pub fn supports_udp(&self) -> bool {
        match self.transport {
            UplinkTransport::Ws => self.udp_ws_url.is_some(),
            UplinkTransport::Vless => self.vless_dial_url().is_some(),
            UplinkTransport::Shadowsocks => self.udp_addr.is_some(),
        }
    }

    pub fn tcp_dial_url(&self) -> Option<&Url> {
        match self.transport {
            UplinkTransport::Vless => self.vless_dial_url(),
            UplinkTransport::Ws => self.tcp_ws_url.as_ref(),
            UplinkTransport::Shadowsocks => None,
        }
    }

    pub fn udp_dial_url(&self) -> Option<&Url> {
        match self.transport {
            UplinkTransport::Vless => self.vless_dial_url(),
            UplinkTransport::Ws => self.udp_ws_url.as_ref(),
            UplinkTransport::Shadowsocks => None,
        }
    }

    fn vless_dial_url(&self) -> Option<&Url> {
        match self.vless_mode {
            TransportMode::XhttpH1 | TransportMode::XhttpH2 | TransportMode::XhttpH3 => {
                self.vless_xhttp_url.as_ref()
            },
            _ => self.vless_ws_url.as_ref(),
        }
    }

    pub fn tcp_dial_mode(&self) -> TransportMode {
        match self.transport {
            UplinkTransport::Vless => self.vless_mode,
            _ => self.tcp_mode,
        }
    }

    pub fn udp_dial_mode(&self) -> TransportMode {
        match self.transport {
            UplinkTransport::Vless => self.vless_mode,
            _ => self.udp_mode,
        }
    }
}

// ── UplinkConfig ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UplinkConfig {
    pub name: String,
    pub transport: UplinkTransport,
    /// `transport = "ws"` only. None for vless/shadowsocks.
    pub tcp_ws_url: Option<Url>,
    /// `transport = "ws"` only. Meaningless for vless/shadowsocks.
    pub tcp_mode: TransportMode,
    /// `transport = "ws"` only. None for vless/shadowsocks.
    pub udp_ws_url: Option<Url>,
    /// `transport = "ws"` only. Meaningless for vless/shadowsocks.
    pub udp_mode: TransportMode,
    /// `transport = "vless"` only. Single WS URL serving both TCP
    /// and UDP — required when `vless_mode` is one of the WS or QUIC
    /// variants.
    pub vless_ws_url: Option<Url>,
    /// `transport = "vless"` only. Base URL for XHTTP packet-up;
    /// session id is appended at dial time. Required when
    /// `vless_mode` is `XhttpH1` / `XhttpH2` / `XhttpH3`.
    pub vless_xhttp_url: Option<Url>,
    /// `transport = "vless"` only.
    pub vless_mode: TransportMode,
    pub tcp_addr: Option<ServerAddr>,
    pub udp_addr: Option<ServerAddr>,
    pub cipher: CipherKind,
    pub password: String,
    pub weight: f64,
    pub fwmark: Option<u32>,
    pub ipv6_first: bool,
    /// Present when `transport = "vless"`. Raw 16-byte user id; parsed from
    /// the config string via `outline_transport::vless::parse_uuid`.
    pub vless_id: Option<[u8; 16]>,
    /// Per-uplink override for the browser fingerprint diversification
    /// strategy. `None` means inherit the process-wide value wired by
    /// [`outline_transport::init_fingerprint_profile_strategy`]; `Some`
    /// pins this uplink to a specific strategy (most usefully
    /// `Strategy::None` for an uplink that must keep a byte-identical
    /// xray-style wire shape, while siblings opt into `PerHostStable`).
    pub fingerprint_profile: Option<outline_transport::FingerprintProfileStrategy>,
    /// Optional list of fallback transports tried in order when the primary
    /// transport on this uplink fails to dial / chunk-0. Fallbacks share the
    /// parent's identity (`name`, `weight`, `group`) — they are not separate
    /// uplinks from the load-balancer's point of view. See
    /// [`FallbackTransport`] for the wire-shape fields each fallback carries.
    /// Empty by default; populated from `[[outline.uplinks.fallbacks]]` in
    /// the TOML config.
    pub fallbacks: Vec<FallbackTransport>,
    /// Random forward-only wire rotation. When `true`, the wire chain
    /// `[primary, fallbacks…]` is reshuffled once before this uplink is
    /// handed to the manager (so each process restart picks a different
    /// ordering) and the per-transport active-wire state machine
    /// surrenders to uplink-failover after one full pass through the
    /// chain without a single successful wire dial. See
    /// `UplinkSection::shuffle_wires` in the TOML schema for the full
    /// operator-facing description.
    pub shuffle_wires: bool,
    /// Per-uplink carrier-downgrade switch. `true` (default) keeps the
    /// legacy `h3 → h2 → h1` (and `xhttp_h3 → xhttp_h2 → xhttp_h1`)
    /// descent inside each WS / VLESS-XHTTP wire; `false` makes the
    /// proxy skip the vertical cascade entirely — failures roll over
    /// to the next wire (under `shuffle_wires = true`) or trigger the
    /// legacy wire-advance (without `shuffle_wires`) without spending
    /// `mode_downgrade_secs` per rank. See
    /// `UplinkSection::carrier_downgrade` in the TOML schema for the
    /// operator-facing description.
    pub carrier_downgrade: bool,
}

impl UplinkConfig {
    /// True when the parent's primary transport supports UDP. To check
    /// whether *any* (primary or fallback) wire on this uplink supports UDP,
    /// use [`UplinkConfig::supports_udp_any`].
    pub fn supports_udp(&self) -> bool {
        match self.transport {
            UplinkTransport::Ws => self.udp_ws_url.is_some(),
            UplinkTransport::Vless => self.vless_dial_url().is_some(),
            UplinkTransport::Shadowsocks => self.udp_addr.is_some(),
        }
    }

    /// True when at least one configured wire (primary or any fallback) on
    /// this uplink can carry UDP traffic. Used by the candidate filter so an
    /// uplink whose primary is UDP-incapable but whose fallback is, still
    /// shows up for UDP dispatch.
    pub fn supports_udp_any(&self) -> bool {
        self.supports_udp() || self.fallbacks.iter().any(|fb| fb.supports_udp())
    }

    /// URL to dial for TCP-style sessions. For VLESS this is either
    /// `vless_ws_url` or `vless_xhttp_url` depending on `vless_mode`;
    /// for WS this is `tcp_ws_url`. Shadowsocks returns None.
    pub fn tcp_dial_url(&self) -> Option<&Url> {
        match self.transport {
            UplinkTransport::Vless => self.vless_dial_url(),
            UplinkTransport::Ws => self.tcp_ws_url.as_ref(),
            UplinkTransport::Shadowsocks => None,
        }
    }

    /// URL to dial for UDP-style sessions. VLESS UDP rides the same
    /// session as TCP (mux.cool / XUDP), so this collapses to the
    /// same URL as `tcp_dial_url`. WS uses the dedicated `udp_ws_url`.
    pub fn udp_dial_url(&self) -> Option<&Url> {
        match self.transport {
            UplinkTransport::Vless => self.vless_dial_url(),
            UplinkTransport::Ws => self.udp_ws_url.as_ref(),
            UplinkTransport::Shadowsocks => None,
        }
    }

    /// Picks the right VLESS dial URL based on the configured mode.
    /// Centralised here so callers do not duplicate the WS-vs-XHTTP
    /// branch each time the dial target is needed.
    fn vless_dial_url(&self) -> Option<&Url> {
        match self.vless_mode {
            TransportMode::XhttpH1 | TransportMode::XhttpH2 | TransportMode::XhttpH3 => {
                self.vless_xhttp_url.as_ref()
            },
            _ => self.vless_ws_url.as_ref(),
        }
    }

    /// WS transport mode for TCP-style sessions, abstracting the
    /// per-transport mode field.
    pub fn tcp_dial_mode(&self) -> TransportMode {
        match self.transport {
            UplinkTransport::Vless => self.vless_mode,
            _ => self.tcp_mode,
        }
    }

    /// WS transport mode for UDP-style sessions, abstracting the
    /// per-transport mode field.
    pub fn udp_dial_mode(&self) -> TransportMode {
        match self.transport {
            UplinkTransport::Vless => self.vless_mode,
            _ => self.udp_mode,
        }
    }

    /// Materialise a per-wire view of this uplink as a synthetic
    /// `UplinkConfig`. `wire_index = 0` returns the primary; `wire_index
    /// = N` returns the `N - 1`-th fallback rendered as a standalone
    /// uplink (its own `transport`, dial URLs, and credentials, with
    /// `fallbacks` cleared so probe code paths can treat it as a single
    /// wire). The synthetic uplink keeps the parent's `name` and
    /// `weight` for log/metric attribution.
    ///
    /// Used by the per-wire probe walks: when primary is failing, the
    /// scheduler probes the active fallback wire to validate it without
    /// re-implementing the per-protocol probe logic.
    ///
    /// Returns `None` for `wire_index` outside `0..=fallbacks.len()`.
    pub fn wire_view(&self, wire_index: usize) -> Option<UplinkConfig> {
        if wire_index == 0 {
            let mut view = self.clone();
            view.fallbacks = Vec::new();
            return Some(view);
        }
        let fb = self.fallbacks.get(wire_index - 1)?;
        Some(UplinkConfig {
            name: self.name.clone(),
            transport: fb.transport,
            tcp_ws_url: fb.tcp_ws_url.clone(),
            tcp_mode: fb.tcp_mode,
            udp_ws_url: fb.udp_ws_url.clone(),
            udp_mode: fb.udp_mode,
            vless_ws_url: fb.vless_ws_url.clone(),
            vless_xhttp_url: fb.vless_xhttp_url.clone(),
            vless_mode: fb.vless_mode,
            tcp_addr: fb.tcp_addr.clone(),
            udp_addr: fb.udp_addr.clone(),
            cipher: fb.cipher,
            password: fb.password.clone(),
            weight: self.weight,
            fwmark: fb.fwmark,
            ipv6_first: fb.ipv6_first,
            vless_id: fb.vless_id,
            fingerprint_profile: fb.fingerprint_profile.clone(),
            fallbacks: Vec::new(),
            // wire_view materialises a synthetic single-wire uplink for
            // probe walks — round-rotation semantics are meaningless on a
            // chain of one. Always false on the synthetic side regardless
            // of the parent's setting.
            shuffle_wires: false,
            // Carrier-downgrade is a per-WIRE behaviour, so we honour the
            // parent's setting on the synthetic wire view — a fallback
            // wire being probed should observe the same descent /
            // no-descent policy the parent uplink configured.
            carrier_downgrade: self.carrier_downgrade,
        })
    }
}

// ── ProbeConfig ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub interval: Duration,
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub max_dials: usize,
    pub min_failures: usize,
    /// Number of probe attempts per cycle. If any attempt succeeds the cycle is
    /// counted as a success. Retries are separated by a short pause (500 ms),
    /// so the total time per cycle can be up to
    /// `attempts × (per-transport probe timeout budget + 500 ms)`. Default: 2.
    pub attempts: usize,
    /// When true (default), probe cycles are skipped on uplinks that are
    /// already carrying real traffic, are probe-confirmed healthy, and have
    /// no active runtime cooldown — the uplink is proving itself by data
    /// transfer, so re-validating with extra handshakes is wasted load on
    /// the upstream rate limiter. Set to false to disable this optimisation
    /// and run probes on every interval regardless of traffic, e.g. when an
    /// operator wants always-on probe metric coverage on dashboards even
    /// for the active uplink. Note that an in-flight chunk-0 streak still
    /// overrides the skip independently of this flag — the chunk-0 signal
    /// is too important to silence even when probes are otherwise quiet.
    pub skip_when_active: bool,
    /// Liveness-probe override: even when [`Self::skip_when_active`] is
    /// true and the activity check would otherwise skip the cycle, run
    /// the probe at least once every `liveness_interval` so dashboard
    /// `probe_runs_total{probe=...}` rate stays non-zero on healthy
    /// always-active uplinks and operators get continuous coverage of
    /// "can this uplink still reach the configured probe target". Set
    /// to `Duration::ZERO` to disable the override (legacy behaviour:
    /// skip can hold forever as long as traffic flows). Default is 5
    /// minutes, picked to be comfortably above the typical
    /// `probe.interval` so the override does not trigger every cycle
    /// but still surfaces "probe target unreachable" within a few
    /// minutes of the underlying problem.
    pub liveness_interval: Duration,
    pub ws: WsProbeConfig,
    pub http: Option<HttpProbeConfig>,
    pub dns: Option<DnsProbeConfig>,
    pub tcp: Option<TcpProbeConfig>,
    pub tls: Option<TlsProbeConfig>,
}

impl ProbeConfig {
    pub fn enabled(&self) -> bool {
        self.ws.enabled
            || self.http.is_some()
            || self.dns.is_some()
            || self.tcp.is_some()
            || self.tls.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct WsProbeConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct HttpProbeConfig {
    pub urls: Vec<Url>,
    cursor: Arc<AtomicUsize>,
}

impl HttpProbeConfig {
    pub fn new(urls: Vec<Url>) -> Result<Self> {
        if urls.is_empty() {
            return Err(anyhow!("http probe requires at least one URL"));
        }
        Ok(Self {
            urls,
            cursor: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Atomically advance the rotation cursor and return the next URL. Each
    /// call yields the next entry in the configured list, wrapping at the
    /// end so probes spread their load across endpoints rather than hammering
    /// a single one — this also makes per-site outages visible instead of
    /// being masked by a single still-reachable URL.
    pub fn next_url(&self) -> &Url {
        let i = self.cursor.fetch_add(1, Ordering::Relaxed) % self.urls.len();
        &self.urls[i]
    }
}

#[derive(Debug, Clone)]
pub struct DnsProbeConfig {
    pub server: String,
    pub port: u16,
    pub name: String,
}

impl DnsProbeConfig {
    pub fn target_addr(&self) -> Result<TargetAddr> {
        if let Ok(ip) = self.server.parse::<IpAddr>() {
            Ok(match ip {
                IpAddr::V4(v4) => TargetAddr::IpV4(v4, self.port),
                IpAddr::V6(v6) => TargetAddr::IpV6(v6, self.port),
            })
        } else {
            Ok(TargetAddr::Domain(self.server.clone(), self.port))
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpProbeConfig {
    pub host: String,
    pub port: u16,
}

/// One target for the TLS handshake-only data-path probe. Carries the SNI to
/// advertise on `ClientHello` (`host`) and the upstream port to dial through
/// the tunnel (typically `443`). The probe loop rotates through the configured
/// list one entry per cycle, exactly like [`HttpProbeConfig`].
#[derive(Debug, Clone)]
pub struct TlsProbeTarget {
    pub host: String,
    pub port: u16,
}

/// TLS handshake-only probe configuration. Performs `ClientHello → ServerHello
/// / Certificate → Finished → close_notify` through the uplink tunnel against
/// a real product SNI (e.g. `www.youtube.com:443`) — without any HTTP exchange
/// after the handshake. Reproduces the user-flow `chunk0_timeout` pattern when
/// upstream filtering silently drops `ServerHello` bytes for specific SNIs;
/// the plain HTTP probe never exercises TLS at all and so is blind to that
/// failure mode.
#[derive(Debug, Clone)]
pub struct TlsProbeConfig {
    pub targets: Vec<TlsProbeTarget>,
    cursor: Arc<AtomicUsize>,
}

impl TlsProbeConfig {
    pub fn new(targets: Vec<TlsProbeTarget>) -> Result<Self> {
        if targets.is_empty() {
            return Err(anyhow!("tls probe requires at least one target"));
        }
        Ok(Self {
            targets,
            cursor: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Atomically advance the rotation cursor and return the next target.
    /// Each call yields the next entry in the configured list, wrapping at
    /// the end so cycles spread across SNIs and per-SNI filtering is
    /// surfaced instead of being masked by a single still-reachable target.
    pub fn next_target(&self) -> &TlsProbeTarget {
        let i = self.cursor.fetch_add(1, Ordering::Relaxed) % self.targets.len();
        &self.targets[i]
    }
}

// ── LoadBalancingConfig ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LoadBalancingConfig {
    pub mode: LoadBalancingMode,
    pub routing_scope: RoutingScope,
    pub sticky_ttl: Duration,
    pub hysteresis: Duration,
    pub failure_cooldown: Duration,
    /// Maximum silence window to wait for the first upstream response bytes
    /// before TCP chunk-0 failover is allowed.
    pub tcp_chunk0_failover_timeout: Duration,
    pub warm_standby_tcp: usize,
    pub warm_standby_udp: usize,
    pub rtt_ewma_alpha: f64,
    pub failure_penalty: Duration,
    pub failure_penalty_max: Duration,
    pub failure_penalty_halflife: Duration,
    /// How long to downgrade from H3 to H2 after an H3 runtime error.
    pub mode_downgrade_duration: Duration,
    /// In `routing_scope = "global"`, controls whether UDP health gates the
    /// active uplink alongside TCP health. When `false` (default), UDP probe
    /// failures and UDP cooldown are informational only — used in score
    /// ranking and surfaced in metrics, but they do not kick the active
    /// uplink as long as TCP is healthy. When `true`, the legacy strict
    /// behaviour is preserved: any UDP-unhealthy state on the active uplink
    /// drops it from selection (as in pre-1.4.x builds).
    ///
    /// The lenient default matches the existing documented intent of global
    /// scope ("global routing should primarily follow TCP quality"; UDP is a
    /// "weak tie-breaker") and stops the cascade-flap mode where flaky UDP
    /// paths (e.g. XHTTP/H3 on a network that drops QUIC) repeatedly demoted
    /// the active uplink even though TCP and the bulk of traffic were fine.
    pub global_udp_strict_health: bool,
    /// Time window over which consecutive runtime (data-plane) failures are
    /// counted toward the `runtime_failure_threshold = probe.min_failures`
    /// health-flip escalation. A new runtime failure arriving more than
    /// `runtime_failure_window` after the previous one resets the streak to
    /// `1` instead of incrementing — so two transient errors spaced minutes
    /// apart on an idle uplink no longer escalate to a spurious health flip.
    /// Setting this to `Duration::ZERO` keeps the legacy behaviour (no decay,
    /// counter only resets on successful traffic or successful probe).
    pub runtime_failure_window: Duration,
    /// Time window over which consecutive **chunk-0 timeouts** on a single
    /// uplink/transport are counted toward the same
    /// `probe.min_failures`-based health-flip escalation. Chunk-0 timeouts
    /// indicate a silent upstream — the connection handshake succeeded,
    /// but no response bytes ever arrived within the deadline — which the
    /// handshake-only probe cannot detect. They occur sparsely (often a
    /// few minutes apart on a slowly-degrading server), so the generic
    /// `runtime_failure_window` (default 60 s) decays the streak before
    /// it ever reaches the threshold and the active uplink stays pinned
    /// to a broken upstream. This window is independent and typically
    /// much wider (default 5 min). A chunk-0 timeout arriving more than
    /// `chunk0_failure_window` after the previous one resets the
    /// chunk-0 streak to `1`. `Duration::ZERO` disables the dedicated
    /// counter (chunk-0 timeouts then only feed the generic
    /// `consecutive_runtime_failures` like any other failure).
    pub chunk0_failure_window: Duration,
    /// Interval at which WS ping frames are sent on idle UDP data-path connections
    /// to prevent NAT/firewall timeout disconnections. None disables keepalive.
    pub udp_ws_keepalive_interval: Option<Duration>,
    /// Interval at which WS ping frames are sent on idle TCP data-path connections.
    /// Currently wired only for VLESS-over-WS — Shadowsocks-over-WS upstreams
    /// reject mid-session WS Pings (they corrupt the SS framing state), so SS
    /// uses application-level `tcp_active_keepalive_interval` instead. None
    /// disables the WS-level keepalive on the active VLESS TCP session.
    pub tcp_ws_keepalive_interval: Option<Duration>,
    /// How often to ping warm-standby TCP pool connections to keep them alive through
    /// NAT/firewall idle timeouts. Runs in addition to the 15-second validation cycle.
    /// None disables the extra keepalive loop (validation every 15 s still runs).
    pub tcp_ws_standby_keepalive_interval: Option<Duration>,
    /// How often to send a Shadowsocks keepalive frame on an idle active SOCKS TCP
    /// session (SS2022 only — SS1 uplinks treat this as a no-op). Defeats upstream
    /// proxy or NAT idle-timeout disconnections for long-lived flows like SSH.
    /// These keepalives preserve the transport path but do NOT reset the
    /// session-level `socks_upstream_idle` watcher; only real payload bytes do.
    /// None disables per-session keepalive (relies solely on OS TCP keepalive).
    pub tcp_active_keepalive_interval: Option<Duration>,
    /// How often to ping the cached probe pipes (warm-UDP/TCP slots used to
    /// reuse a VLESS DNS/HTTP probe transport across cycles) so the
    /// upstream server-side NAT entry / HTTP keep-alive socket does not
    /// time out between probe cycles. The keepalive runs the same DNS
    /// query / HEAD request the regular probe would, but only against
    /// already-cached pipes — empty slots are left alone for the next
    /// regular probe to fill. None disables the keepalive (cached pipes
    /// then survive only if `probe.interval` is short enough on its own).
    pub warm_probe_keepalive_interval: Option<Duration>,
    /// When false (default), the active uplink is only replaced when it fails.
    /// When true, traffic returns to the highest-priority healthy uplink once it
    /// has been stable for `min_failures` consecutive probe cycles.
    pub auto_failback: bool,
    /// Bounds on the per-uplink VLESS UDP session mux: max concurrent sessions
    /// (LRU-evicted beyond the cap), per-session idle timeout, and janitor
    /// scan interval. Ignored for non-VLESS uplinks.
    pub vless_udp_mux_limits: VlessUdpMuxLimits,
    /// Maximum bytes of recently-sent uplink payload kept buffered for
    /// the Ack-Prefix Protocol mid-session retry path. The pinned-relay
    /// uplink task pushes every chunk into a bounded ring before
    /// sending; on a mid-session transport reset the relay re-dials
    /// with `X-Outline-Resume-Ack-Prefix: 1`, parses the server-reported
    /// `up_acked` offset from the new stream's first SS-AEAD chunk,
    /// and replays the buffered tail so the upstream never sees a
    /// duplicate or missing byte.
    ///
    /// `0` disables retry entirely (and the buffer is never allocated).
    /// Default: 256 KiB — large enough to absorb most HTTP request
    /// bodies that benefit from retry, small enough that buffering N
    /// concurrent pinned sessions does not pressure RSS. Single-chunk
    /// pushes larger than the cap surface a hard error and burn the
    /// retry budget for that session, since a torn replay would be
    /// undetectable downstream.
    pub tcp_mid_session_retry_buffer_bytes: usize,
    /// Maximum number of mid-session redial attempts allowed per
    /// pinned SOCKS TCP session before the relay propagates the
    /// transport error. Each attempt costs one redial + one replay
    /// of the buffered uplink tail; the bound prevents pathological
    /// thrash on persistent server-side failure (e.g. an upstream
    /// the server can no longer reach, where every redial succeeds
    /// at the WS layer but the upstream relay errors immediately
    /// again).
    ///
    /// `0` disables mid-session retry entirely — equivalent to
    /// setting `tcp_mid_session_retry_buffer_bytes = 0`. Default:
    /// `1` (one retry per session, matching the original v1
    /// behaviour). Higher values are valid but provide diminishing
    /// returns: most retriable failures recover on the first
    /// attempt; persistent failures consume budget without
    /// resolving.
    pub tcp_mid_session_retry_budget: u8,
    /// Behaviour when an uplink chunk is larger than the mid-session
    /// retry buffer cap (`tcp_mid_session_retry_buffer_bytes`). The
    /// chunk on its own cannot be replayed, so the session's
    /// retry-correctness contract is irrecoverably broken from this
    /// point. The two policies trade liveness against replay
    /// guarantees:
    ///
    /// * `Soft` (default, matches v1.1 behaviour) — fire the
    ///   `outcome="buffer_overflow"` metric, send the oversized
    ///   chunk through anyway, and continue the session. Future
    ///   retries on this session will surface `failed_replay`
    ///   because the ring's `total_sent` advanced past what it can
    ///   reproduce. Optimises for active-session liveness: the
    ///   user does not see their session die mid-stream just
    ///   because one large chunk happened.
    /// * `Hard` — drop the session immediately. Guarantees that
    ///   any session the orchestrator considers retry-eligible
    ///   actually IS retry-eligible (no surprise `failed_replay`
    ///   later). Surfaces the `buffer_overflow` metric and a
    ///   transport-level error to the caller.
    ///
    /// Only relevant when `tcp_mid_session_retry_buffer_bytes > 0`
    /// AND `tcp_mid_session_retry_budget > 0`; with retry disabled
    /// the ring is never allocated and overflow cannot occur.
    pub tcp_mid_session_retry_overflow_policy: OverflowPolicy,
    /// Hard upper bound on how long the orchestrator waits for the
    /// server to emit the v1 Ack-Prefix control frame on a successful
    /// resume hit. The server's emit happens immediately on resume —
    /// the only way this fires is a broken network path or a
    /// misbehaving server, in which case we want to fail fast and
    /// drop the session rather than block the entire pinned relay.
    ///
    /// Default: 5 seconds — comfortably above any reasonable RTT
    /// (including high-latency satellite + cellular paths) but short
    /// enough that a stuck session does not pin its own state for an
    /// observable user-visible delay. Tighter values are valid on
    /// known-low-RTT deployments; significantly larger values
    /// indicate the deployment has retry behaviour problems the
    /// timeout is masking.
    pub tcp_mid_session_retry_consume_timeout: Duration,
    /// Whether the client opts into the v2 Symmetric Downlink Replay
    /// protocol on mid-session retry redials. Per spec v2 is gated on
    /// v1: the client only advertises
    /// `X-Outline-Resume-Symmetric-Replay: 1` when it is also
    /// advertising `X-Outline-Resume-Ack-Prefix: 1`, AND the v1.x
    /// retry stack is enabled (`tcp_mid_session_retry_buffer_bytes > 0`
    /// and `tcp_mid_session_retry_budget > 0`).
    ///
    /// Default: `true`. When the wire-protocol partner is known to
    /// only support v1.x (older `outline-ss-rust`) the operator can
    /// flip this to `false` to suppress the v2 advertise without
    /// disabling v1.x retry. See `docs/SESSION-RESUMPTION.md` (server
    /// repo) § Symmetric Downlink Replay (v2).
    pub tcp_symmetric_replay_enabled: bool,
    /// Hard cap on the v2 `replay_len` the client will accept from
    /// the server. Replies above this drop the session per spec —
    /// guards against a malicious or misbehaving server inducing
    /// unbounded memory pressure on the client.
    ///
    /// Default: `1_048_576` bytes (1 MiB). Servers in a sane
    /// deployment configure `downlink_buffer_bytes` well below this
    /// cap (default 64 KiB), so the cap fires only on a genuinely
    /// hostile peer.
    pub tcp_symmetric_replay_max_bytes: usize,
}

/// Policy for the `tcp_mid_session_retry_overflow_policy` knob.
/// See the field docs on [`LoadBalancingConfig`] for semantics.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverflowPolicy {
    /// Send the oversized chunk and keep the session alive; future
    /// retries will surface `failed_replay`. Default.
    #[default]
    Soft,
    /// Drop the session immediately on the first oversized chunk.
    Hard,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingMode {
    ActiveActive,
    ActivePassive,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoutingScope {
    PerFlow,
    PerUplink,
    Global,
}
