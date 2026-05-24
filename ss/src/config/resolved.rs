use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

use anyhow::Result;

use super::{
    CipherKind, ConfigError, ControlConfig, DashboardConfig, HttpFallbackConfig, SniFallbackConfig,
    TlsCertEntry, TuningProfile, UserEntry, file::SessionResumptionSection,
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
    pub ss_listen: Option<SocketAddr>,
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
    /// How often to re-enumerate the outbound interface's IPv6 addresses.
    pub outbound_ipv6_refresh_secs: u64,
    pub ws_path_tcp: String,
    pub ws_path_udp: String,
    pub ws_path_vless: Option<String>,
    /// Base path under which the server accepts VLESS-over-XHTTP
    /// packet-up. The actual axum/h3 routes registered are
    /// `<base>/{id}` for each base; `id` is the opaque session
    /// token the client picks. None disables XHTTP.
    pub xhttp_path_vless: Option<String>,
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
    /// Reverse-proxy unmatched HTTP requests to an upstream backend.
    /// `None` keeps the legacy 404 behaviour. Configure via
    /// `[http_fallback]` in the config file.
    pub http_fallback: Option<HttpFallbackConfig>,
    /// SNI-routed L4 fallback. When set and the inbound TCP listener
    /// terminates TLS, foreign SNIs are spliced as raw TCP to the
    /// configured backend. `None` keeps every TLS connection on the
    /// local terminator.
    pub sni_fallback: Option<SniFallbackConfig>,
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
        self.listen.is_some() || self.h3_enabled() || self.ss_listen.is_some()
    }
}
