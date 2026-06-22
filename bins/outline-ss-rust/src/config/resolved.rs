use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

use anyhow::Result;

use super::{
    CipherKind, ConfigError, ControlConfig, DashboardConfig, HttpFallbackConfig, SniFallbackConfig,
    TlsCertEntry, TuningProfile, UserEntry,
    file::{PaddingSection, SessionResumptionSection},
};

/// ALPN protocols recognised on the HTTP/3 QUIC endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum H3Alpn {
    /// HTTP/3 (with Extended CONNECT WebSocket per RFC 9220).
    H3,
    /// Raw VLESS framed directly over QUIC bidirectional streams.
    Vless,
    /// Raw Shadowsocks AEAD framed directly over QUIC bidirectional streams.
    Ss,
}

impl H3Alpn {
    /// All ALPN identifiers the server should advertise for this
    /// protocol, in preference order (MTU-aware sibling first when
    /// applicable). Newer clients negotiate the MTU-aware variant
    /// and use the oversize-record stream fallback for UDP datagrams
    /// that exceed `Connection::max_datagram_size()`; older clients
    /// negotiate the base ALPN and behave as before.
    pub const fn advertised_alpns(self) -> &'static [&'static [u8]] {
        match self {
            Self::H3 => &[b"h3"],
            Self::Vless => &[b"vless-mtu", b"vless"],
            Self::Ss => &[b"ss-mtu", b"ss"],
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "h3" => Some(Self::H3),
            "vless" | "vless-mtu" => Some(Self::Vless),
            "ss" | "ss-mtu" => Some(Self::Ss),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Path of the config file this `Config` was loaded from, if any.
    /// Preserved so the control plane can persist runtime user mutations
    /// back to the same file that seeded them.
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub config_path: Option<PathBuf>,
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub control: Option<ControlConfig>,
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub dashboard: Option<DashboardConfig>,
    pub listen: Option<SocketAddr>,
    /// Default TLS cert/key for the TCP listener, used when no entry in
    /// [`Self::tls_certs`] matches the inbound SNI (or the client did
    /// not send one). Either both are set or neither.
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    /// Additional cert/key pairs for the TCP listener, dispatched by
    /// SNI at handshake time. Empty means "single-cert mode".
    pub tls_certs: Vec<TlsCertEntry>,
    pub h3_listen: Option<SocketAddr>,
    /// Default TLS cert/key for the QUIC listener; analogous to
    /// [`Self::tls_cert_path`]. When unset, the resolver inherits from
    /// the TCP listener's default cert (see config-loader fallback).
    pub h3_cert_path: Option<PathBuf>,
    pub h3_key_path: Option<PathBuf>,
    /// Additional cert/key pairs for the QUIC listener. Falls back to
    /// [`Self::tls_certs`] when no `[[server.h3.certs]]` table is given
    /// at all.
    pub h3_certs: Vec<TlsCertEntry>,
    /// ALPN protocols advertised on the HTTP/3 QUIC endpoint. Each entry
    /// selects a different transport multiplexed on the same UDP port:
    /// `"h3"` for HTTP/3 + WebSocket-over-HTTP/3 (the default), `"vless"`
    /// for raw VLESS over QUIC streams, `"ss"` for raw Shadowsocks over QUIC
    /// streams. Resolved from `[server.h3].alpn`; defaults to `["h3"]`.
    pub h3_alpn: Vec<H3Alpn>,
    pub metrics_listen: Option<SocketAddr>,
    pub metrics_path: String,
    pub prefer_ipv4_upstream: bool,
    /// If set, upstream IPv6 TCP/UDP sockets bind to a random address drawn
    /// from this prefix (e.g. `2001:db8:dead::/64`) instead of using the
    /// kernel default. See [`crate::outbound`] for details.
    pub outbound_ipv6_prefix: Option<crate::outbound::Ipv6Prefix>,
    /// Alternative to [`Self::outbound_ipv6_prefix`]: a network interface
    /// name (e.g. `eth0`). At runtime the IPv6 addresses assigned to the
    /// interface are enumerated (refreshed periodically) and upstream IPv6
    /// sockets bind to a random one. Useful for DHCPv6/SLAAC deployments
    /// where the prefix/addresses are not known statically.
    pub outbound_ipv6_interface: Option<String>,
    /// Alternative to [`Self::outbound_ipv6_interface`]: derive the current
    /// global /64 from this interface and draw random sources across the whole
    /// prefix (not just configured addresses). Re-derived on refresh, so it
    /// follows a dynamic upstream prefix. Requires the prefix routed back to
    /// the host (NDP proxy / ndppd).
    pub outbound_ipv6_prefix_interface: Option<String>,
    /// How often to re-enumerate the outbound interface's IPv6 addresses
    /// (or re-derive the interface prefix).
    pub outbound_ipv6_refresh_secs: u64,
    /// Pin one outbound IPv6 source address per upstream destination IP for
    /// [`Self::outbound_ipv6_sticky_ttl_secs`] instead of drawing a fresh
    /// random source on every connect. Keeps a Cloudflare `cf_clearance`
    /// challenge (bound to the client source IP) valid across a client's
    /// successive requests. On by default; no effect unless an IPv6
    /// prefix/interface is set.
    pub outbound_ipv6_sticky: bool,
    /// TTL (seconds) for sticky source pins. Should exceed the origin's
    /// challenge-clearance lifetime (Cloudflare's is ~30 min). Default 1800.
    pub outbound_ipv6_sticky_ttl_secs: u64,
    pub ws_path_tcp: String,
    pub ws_path_udp: String,
    /// Combined SS-over-WS path: one path carries both TCP and UDP legs (the
    /// server splits them by the hidden `/{token}` bit). None disables it.
    pub ws_path_ss: Option<String>,
    pub ws_path_vless: Option<String>,
    /// Base path under which the server accepts VLESS-over-XHTTP
    /// packet-up. The actual axum/h3 routes registered are
    /// `<base>/{id}` for each base; `id` is the opaque session
    /// token the client picks. None disables XHTTP.
    pub xhttp_path_vless: Option<String>,
    /// Base path under which the server accepts Shadowsocks-over-XHTTP.
    /// Same route shape as `xhttp_path_vless`; None disables it.
    pub xhttp_path_tcp: Option<String>,
    /// Base path under which the server accepts SS-UDP-over-XHTTP.
    /// Separate from `xhttp_path_tcp` (the TCP path); None disables it.
    pub xhttp_path_udp: Option<String>,
    /// Combined SS-over-XHTTP path: one path carries both TCP and UDP legs
    /// (split by the hidden session-id bit). None disables it.
    pub xhttp_path_ss: Option<String>,
    pub http_root_auth: bool,
    pub http_root_realm: String,
    pub users: Vec<UserEntry>,
    pub method: CipherKind,
    #[cfg_attr(not(feature = "control"), allow(dead_code))]
    pub access_key: AccessKeyConfig,
    /// Resolved tuning knobs (H2/H3 resource limits plus session/NAT timeouts
    /// and global UDP relay cap). Derived from the `tuning_profile` preset
    /// with any per-field overrides from `[tuning]` applied on top. Validated
    /// at config load time.
    pub tuning: TuningProfile,
    /// Resolved cross-transport session-resumption knobs. Defaults to
    /// disabled; opt in via `[session_resumption]` in the config file.
    /// See `docs/SESSION-RESUMPTION.md`.
    pub session_resumption: SessionResumptionConfig,
    /// Resolved carrier-padding knobs (WS/XHTTP record-size obfuscation +
    /// cover traffic, applied per-path). Defaults to disabled; opt in via
    /// `[padding]`. Config-synchronised — both ends must match.
    pub padding: PaddingConfig,
    /// Reverse-proxy unmatched HTTP requests to an upstream backend.
    /// `None` keeps the legacy 404 behaviour. Configure via
    /// `[http_fallback]` in the config file.
    pub http_fallback: Option<HttpFallbackConfig>,
    /// SNI-routed L4 fallback. When set and the inbound TCP listener
    /// terminates TLS, foreign SNIs are spliced as raw TCP to the
    /// configured backend. `None` keeps every TLS connection on the
    /// local terminator.
    pub sni_fallback: Option<SniFallbackConfig>,
    /// Reverse-tunnel dialer (topology A). When `Some` and enabled, the
    /// server dials each configured public `ws` listener over QUIC and
    /// serves raw Shadowsocks on the streams the peer opens. `None` keeps
    /// the listen-only model. See `docs/REVERSE-TUNNEL.md`.
    pub reverse_tunnel: Option<ReverseTunnelConfig>,
}

/// Resolved reverse-tunnel dialer config: one or more public `ws`
/// endpoints to dial. Empty `endpoints` or `enabled = false` means no
/// dialer runs.
#[derive(Debug, Clone)]
pub struct ReverseTunnelConfig {
    pub endpoints: Vec<ReverseTunnelEndpoint>,
}

/// One resolved reverse-tunnel endpoint. The pinned `ws` server-cert
/// fingerprint stays a string and the client cert/key stay paths — all
/// three are parsed/loaded by the dialer at startup (mirrors how the H3
/// listener keeps `h3_cert_path` as a path). A malformed pin or unreadable
/// cert fails that one endpoint's dial loop without aborting the server.
/// Wire protocol carried over a reverse-tunnel carrier. Selects the QUIC
/// ALPN offered and which raw-QUIC accept loop the dialer drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReverseProtocol {
    Ss,
    Vless,
}

#[derive(Debug, Clone)]
pub struct ReverseTunnelEndpoint {
    pub addr: String,
    pub server_name: String,
    pub server_cert_pin: String,
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    /// Wire protocol carried over this carrier (selects ALPN + accept loop).
    pub protocol: ReverseProtocol,
    /// `true` offers the `-mtu` ALPN sibling first; `false` only the base.
    pub mtu: bool,
    pub backoff_min: std::time::Duration,
    pub backoff_max: std::time::Duration,
}

impl ReverseTunnelEndpoint {
    /// ALPN list to offer, MTU-aware sibling first when enabled.
    pub fn advertised_alpns(&self) -> &'static [&'static [u8]] {
        match (self.protocol, self.mtu) {
            (ReverseProtocol::Ss, true) => &[b"ss-mtu", b"ss"],
            (ReverseProtocol::Ss, false) => &[b"ss"],
            (ReverseProtocol::Vless, true) => &[b"vless-mtu", b"vless"],
            (ReverseProtocol::Vless, false) => &[b"vless"],
        }
    }
}

/// Public snapshot of the `[session_resumption]` config. Mirrors
/// `SessionResumptionSection` but with all fields resolved to concrete
/// values (defaults applied).
#[derive(Debug, Clone)]
pub struct SessionResumptionConfig {
    pub enabled: bool,
    pub orphan_ttl_tcp_secs: u64,
    pub orphan_ttl_udp_secs: u64,
    pub orphan_per_user_cap: usize,
    pub orphan_global_cap: usize,
    /// Per-session downlink ring buffer capacity for the v2 Symmetric
    /// Downlink Replay protocol. `0` disables v2 server-side: the
    /// capability is never echoed and ring buffers are never
    /// allocated. See `docs/SESSION-RESUMPTION.md` § Symmetric
    /// Downlink Replay (v2).
    pub downlink_buffer_bytes: usize,
}

impl Default for SessionResumptionConfig {
    fn default() -> Self {
        // Mirrors `docs/SESSION-RESUMPTION.md`. Disabled by default.
        Self {
            enabled: false,
            orphan_ttl_tcp_secs: 30,
            orphan_ttl_udp_secs: 30,
            orphan_per_user_cap: 4,
            orphan_global_cap: 10_000,
            // v2 disabled by default — operators opt in by setting a
            // non-zero value once the wire-protocol partner (newer
            // outline-ws-rust) is rolled out.
            downlink_buffer_bytes: 0,
        }
    }
}

impl SessionResumptionConfig {
    pub(super) fn from_section(section: SessionResumptionSection) -> Self {
        let defaults = Self::default();
        Self {
            enabled: section.enabled.unwrap_or(defaults.enabled),
            orphan_ttl_tcp_secs: section
                .orphan_ttl_tcp_secs
                .unwrap_or(defaults.orphan_ttl_tcp_secs),
            orphan_ttl_udp_secs: section
                .orphan_ttl_udp_secs
                .unwrap_or(defaults.orphan_ttl_udp_secs),
            orphan_per_user_cap: section
                .orphan_per_user_cap
                .unwrap_or(defaults.orphan_per_user_cap),
            orphan_global_cap: section.orphan_global_cap.unwrap_or(defaults.orphan_global_cap),
            downlink_buffer_bytes: section
                .downlink_buffer_bytes
                .unwrap_or(defaults.downlink_buffer_bytes),
        }
    }
}

/// Public snapshot of the `[padding]` config, defaults applied. Mirrors
/// `PaddingSection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingConfig {
    pub enabled: bool,
    pub min_bytes: u16,
    pub max_bytes: u16,
    pub cover: bool,
    pub cover_jitter_min_ms: u64,
    pub cover_jitter_max_ms: u64,
    /// Carrier paths padding applies to. A connection is padded only when its
    /// matched path is in this set, so third-party clients (Happ, Outline,
    /// xray, sing-box) on other paths stay on the plain SS-over-WS/XHTTP wire.
    /// Empty when disabled.
    pub paths: Vec<String>,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        // Disabled by default; the light profile (0..256) applies once
        // enabled. Cover off by default — opt in alongside the rolled-out
        // wire-protocol partner, like session-resumption v2.
        Self {
            enabled: false,
            min_bytes: 0,
            max_bytes: 256,
            cover: false,
            cover_jitter_min_ms: 250,
            cover_jitter_max_ms: 1500,
            paths: Vec::new(),
        }
    }
}

impl PaddingConfig {
    pub(super) fn from_section(section: PaddingSection) -> Self {
        let d = Self::default();
        let min_bytes = section.min_bytes.unwrap_or(d.min_bytes);
        // A max below min is clamped up, so the range is always well-formed
        // (mirrors `PaddingScheme::new`).
        let max_bytes = section.max_bytes.unwrap_or(d.max_bytes).max(min_bytes);
        let cover_jitter_min_ms = section.cover_jitter_min_ms.unwrap_or(d.cover_jitter_min_ms);
        let cover_jitter_max_ms = section
            .cover_jitter_max_ms
            .unwrap_or(d.cover_jitter_max_ms)
            .max(cover_jitter_min_ms);
        Self {
            enabled: section.enabled.unwrap_or(d.enabled),
            min_bytes,
            max_bytes,
            cover: section.cover.unwrap_or(d.cover),
            cover_jitter_min_ms,
            cover_jitter_max_ms,
            paths: section.paths.unwrap_or_default(),
        }
    }

    /// The wire-codec scheme this resolves to. Disabled → no framing, the
    /// carrier stays byte-for-byte unchanged; the transport keys off
    /// [`PaddingScheme::is_enabled`].
    pub fn scheme(&self) -> outline_wire::padding::PaddingScheme {
        if self.enabled {
            outline_wire::padding::PaddingScheme::new(self.min_bytes, self.max_bytes)
        } else {
            outline_wire::padding::PaddingScheme::disabled()
        }
    }

    /// Whether to emit idle cover frames: padding on *and* cover requested.
    pub fn cover_enabled(&self) -> bool {
        self.enabled && self.cover
    }

    /// Whether padding applies to a connection whose matched carrier path is
    /// `path`. Only listed paths are padded; everything else (third-party
    /// clients) stays on the plain wire.
    pub fn applies_to(&self, path: &str) -> bool {
        self.enabled && self.paths.iter().any(|p| p == path)
    }

    /// The padding scheme a connection on `path` should use: the configured
    /// range when padding [`Self::applies_to`] this path, otherwise
    /// [`PaddingScheme::disabled`] (no framing — the plain wire). This is the
    /// per-path resolver the transport handlers call at handshake time.
    pub fn scheme_for_path(&self, path: &str) -> outline_wire::padding::PaddingScheme {
        if self.applies_to(path) {
            self.scheme()
        } else {
            outline_wire::padding::PaddingScheme::disabled()
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccessKeyConfig {
    pub public_host: Option<String>,
    pub public_scheme: String,
    pub access_key_url_base: Option<String>,
    pub access_key_file_extension: String,
}

impl Default for AccessKeyConfig {
    fn default() -> Self {
        Self {
            public_host: None,
            public_scheme: "wss".to_owned(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".to_owned(),
        }
    }
}

impl Config {
    pub fn effective_users(&self) -> Result<Vec<UserEntry>, ConfigError> {
        let users = self.users.clone();
        if users
            .iter()
            .all(|user| user.password.is_none() && user.vless_id.is_none())
        {
            return Err(ConfigError::MissingUsers);
        }

        let mut seen = HashSet::with_capacity(users.len());
        for user in &users {
            if !seen.insert(user.id.clone()) {
                return Err(ConfigError::DuplicateUserId(user.id.clone()));
            }
        }

        Ok(users.into_iter().filter(UserEntry::is_enabled).collect())
    }

    pub fn user_entries(&self) -> Result<Vec<UserEntry>, ConfigError> {
        Ok(self
            .effective_users()?
            .into_iter()
            .filter(|user| user.password.is_some())
            .collect())
    }

    pub fn h3_enabled(&self) -> bool {
        self.h3_default_cert_pair_set() || !self.h3_certs.is_empty()
    }

    pub fn tcp_tls_enabled(&self) -> bool {
        self.tcp_default_cert_pair_set() || !self.tls_certs.is_empty()
    }

    pub(super) fn tcp_default_cert_pair_set(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    pub(super) fn h3_default_cert_pair_set(&self) -> bool {
        self.h3_cert_path.is_some() && self.h3_key_path.is_some()
    }

    pub fn metrics_enabled(&self) -> bool {
        self.metrics_listen.is_some()
    }

    pub fn effective_h3_listen(&self) -> Option<SocketAddr> {
        self.h3_enabled().then_some(self.h3_listen).flatten()
    }

    pub fn data_plane_listener_enabled(&self) -> bool {
        self.listen.is_some() || self.h3_enabled()
    }
}
