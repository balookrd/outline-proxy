use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::{CipherKind, TuningOverrides, TuningPreset, UserEntry};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileConfig {
    #[serde(default)]
    pub server: Option<ServerSection>,
    #[serde(default)]
    pub metrics: Option<MetricsSection>,
    #[serde(default)]
    pub outbound: Option<OutboundSection>,
    #[serde(default)]
    pub websocket: Option<WebsocketSection>,
    #[serde(default)]
    pub http_root: Option<HttpRootSection>,
    #[serde(default)]
    pub access_keys: Option<AccessKeysSection>,
    #[serde(default)]
    pub shadowsocks: Option<ShadowsocksSection>,
    #[serde(default)]
    pub users: Option<Vec<UserEntry>>,
    pub tuning_profile: Option<TuningPreset>,
    #[serde(default)]
    pub tuning: Option<TuningOverrides>,
    #[serde(default)]
    pub control: Option<ControlFileConfig>,
    #[serde(default)]
    pub dashboard: Option<DashboardFileConfig>,
    #[serde(default)]
    pub session_resumption: Option<SessionResumptionSection>,
    #[serde(default)]
    pub padding: Option<PaddingSection>,
    #[serde(default)]
    pub http_fallback: Option<HttpFallbackSection>,
    #[serde(default)]
    pub sni_fallback: Option<SniFallbackSection>,
    /// Reverse-tunnel dialer (topology A): this server dials out to one or
    /// more public `outline-ws-rust` listeners over QUIC instead of (or in
    /// addition to) listening locally. `None` keeps the listen-only model.
    #[serde(default)]
    pub reverse_tunnel: Option<ReverseTunnelSection>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReverseTunnelSection {
    /// Master switch. When absent or `false`, no reverse dialer runs even
    /// if endpoints are listed.
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub endpoints: Option<Vec<ReverseTunnelEndpointSection>>,
}

/// One public `ws` listener this server dials. Each becomes an independent
/// reconnect loop carrying raw Shadowsocks over the QUIC streams the `ws`
/// peer opens per SOCKS5/TUN session.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReverseTunnelEndpointSection {
    /// `host:port` of the public `ws` QUIC listener. `host` may be a DNS
    /// name (resolved at dial time) or a literal IP.
    pub addr: String,
    /// TLS SNI / server name presented in the ClientHello. Defaults to the
    /// host part of `addr` when omitted.
    #[serde(default)]
    pub server_name: Option<String>,
    /// SHA-256 fingerprint of the `ws` server certificate to pin: 64 hex
    /// chars (optionally colon-separated) or base64 of 32 bytes. Replaces
    /// webpki validation (CDN fronting is not applicable to the reverse
    /// carrier).
    pub server_cert_pin: String,
    /// Client certificate + key presented for mTLS. The `ws` peer pins this
    /// cert's fingerprint to authenticate this server.
    pub client_cert_path: PathBuf,
    pub client_key_path: PathBuf,
    /// Wire protocol carried over this reverse carrier: `"ss"` (default) or
    /// `"vless"`. Selects the QUIC ALPN offered (`ss`/`ss-mtu` vs
    /// `vless`/`vless-mtu`) and which raw-QUIC accept loop runs. The `ws`
    /// peer entry must declare the matching protocol.
    #[serde(default)]
    pub protocol: Option<String>,
    /// `true` (default) offers the `-mtu` ALPN sibling first so the
    /// oversize-record stream fallback is available; `false` offers only
    /// the base ALPN.
    #[serde(default)]
    pub mtu: Option<bool>,
    /// Reconnect backoff floor / ceiling in seconds. Defaults 1 / 60.
    #[serde(default)]
    pub backoff_min_secs: Option<u64>,
    #[serde(default)]
    pub backoff_max_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerSection {
    pub listen: Option<SocketAddr>,
    /// Default TLS cert for the TCP listener. Legacy alias `tls_cert_path`
    /// is accepted for backward compat with older configs.
    #[serde(default, alias = "tls_cert_path")]
    pub cert_path: Option<PathBuf>,
    #[serde(default, alias = "tls_key_path")]
    pub key_path: Option<PathBuf>,
    /// Optional list of additional cert/key pairs selected by SNI on the
    /// TCP listener. When present, the listener uses an SNI resolver
    /// instead of `with_single_cert`; `cert_path`/`key_path` (if any)
    /// becomes the default returned when SNI matches none of the entries.
    #[serde(default)]
    pub certs: Option<Vec<TlsCertSection>>,
    #[serde(default)]
    pub h3: Option<ServerH3Section>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerH3Section {
    pub listen: Option<SocketAddr>,
    /// Default TLS cert for the QUIC/HTTP-3 listener. When unset, falls
    /// back to `[server].cert_path` so a single config block can serve
    /// both transports off the same cert.
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    /// Optional list of additional cert/key pairs selected by SNI on the
    /// QUIC listener. When unset (i.e. no `[[server.h3.certs]]` table at
    /// all), inherits the array from `[server].certs`.
    #[serde(default)]
    pub certs: Option<Vec<TlsCertSection>>,
    /// ALPN protocols to advertise on the HTTP/3 QUIC endpoint. Allowed values
    /// are `"h3"` (HTTP/3 + WebSocket-over-HTTP/3), `"vless"` (raw VLESS over
    /// QUIC streams) and `"ss"` (raw Shadowsocks over QUIC streams). Defaults
    /// to `["h3"]` when unset.
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
}

/// One entry in `[[server.certs]]` / `[[server.h3.certs]]`. Each maps
/// to one `CertifiedKey` selected at TLS handshake time by SNI.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TlsCertSection {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Explicit list of SNIs this cert serves. Each entry must be an
    /// exact DNS name (no wildcards in the resolver — wildcard certs
    /// still match through their SAN, but the matching is exact at
    /// the resolver level). When omitted, names are extracted from
    /// the certificate's SAN (and CN as a last-resort fallback).
    #[serde(default)]
    pub sni: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MetricsSection {
    pub listen: Option<SocketAddr>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutboundSection {
    pub prefer_ipv4: Option<bool>,
    pub ipv6_prefix: Option<String>,
    pub ipv6_interface: Option<String>,
    pub ipv6_refresh_secs: Option<u64>,
    pub ipv6_sticky: Option<bool>,
    pub ipv6_sticky_ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebsocketSection {
    /// Split SS-over-WebSocket TCP path. Pair with `ws_path_udp` for a
    /// separate UDP path. For one combined path use `ws_path_ss` instead.
    pub ws_path_tcp: Option<String>,
    /// Split SS-over-WebSocket UDP path. Pairs with `ws_path_tcp`.
    pub ws_path_udp: Option<String>,
    /// Combined SS-over-WebSocket path: ONE path carries BOTH the TCP and UDP
    /// legs, with the server telling them apart by a hidden bit in the
    /// `/{token}` URL segment the client appends. The split alternative is
    /// `ws_path_tcp` + `ws_path_udp` on distinct paths; mutually exclusive
    /// with those.
    pub ws_path_ss: Option<String>,
    pub ws_path_vless: Option<String>,
    /// Base path for VLESS-over-XHTTP packet-up. The server registers
    /// `<base>/{id}` for every advertised base, where `{id}` is an
    /// opaque per-session token chosen by the client. Absent (the
    /// default) disables XHTTP.
    pub xhttp_path_vless: Option<String>,
    /// Split SS-over-XHTTP TCP path. Same `<base>/{id}` route shape as
    /// `xhttp_path_vless`, but carries the SS AEAD stream. Pair with
    /// `xhttp_path_udp` for a separate UDP path; for one combined path use
    /// `xhttp_path_ss` instead.
    pub xhttp_path_tcp: Option<String>,
    /// Split SS-UDP-over-XHTTP path. Pairs with `xhttp_path_tcp`, mirroring
    /// `ws_path_tcp` vs `ws_path_udp`.
    pub xhttp_path_udp: Option<String>,
    /// Combined SS-over-XHTTP path: ONE path carries BOTH the TCP and UDP
    /// legs, told apart by the hidden bit in the session-id's first
    /// character. The split alternative is `xhttp_path_tcp` +
    /// `xhttp_path_udp`; mutually exclusive with those.
    pub xhttp_path_ss: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpRootSection {
    pub auth: Option<bool>,
    pub realm: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccessKeysSection {
    pub public_host: Option<String>,
    pub public_scheme: Option<String>,
    pub url_base: Option<String>,
    pub file_extension: Option<String>,
    pub print: Option<bool>,
    pub write_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ShadowsocksSection {
    pub method: Option<CipherKind>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlFileConfig {
    pub listen: Option<SocketAddr>,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DashboardFileConfig {
    pub enabled: Option<bool>,
    pub listen: Option<SocketAddr>,
    pub request_timeout_secs: Option<u64>,
    pub refresh_interval_secs: Option<u64>,
    #[serde(default)]
    pub instances: Option<Vec<DashboardInstanceFileConfig>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DashboardInstanceFileConfig {
    pub name: Option<String>,
    pub control_url: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
}

/// `[http_fallback]` block. When present, requests that do not match a
/// websocket / xhttp / metrics route are reverse-proxied to `backend`
/// instead of returning 404. Useful for masquerading the listener as a
/// regular web service in front of nginx / haproxy / caddy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HttpFallbackSection {
    /// `http://host:port` of the upstream backend. HTTPS, unix sockets,
    /// and path prefixes are not supported in this MVP.
    pub backend: Option<String>,
    /// Per-request connect+response timeout in seconds. Default 30.
    pub request_timeout_secs: Option<u64>,
    /// Append the original peer IP to `X-Forwarded-For`. Default true.
    pub add_x_forwarded_for: Option<bool>,
    /// Set `X-Forwarded-Proto` to `http` / `https` based on whether the
    /// inbound listener is TLS. Default true.
    pub add_x_forwarded_proto: Option<bool>,
    /// Set `X-Forwarded-Host` to the original `Host` header. Default true.
    pub add_x_forwarded_host: Option<bool>,
    /// Wrap the upstream TCP connection in a HAProxy PROXY-protocol
    /// header (`"v1"` text or `"v2"` binary). Default: disabled. The
    /// upstream MUST be configured to expect the matching version
    /// (e.g. nginx `proxy_protocol on;` on the listen directive).
    pub proxy_protocol: Option<String>,
    /// HTTP version to use when talking to the backend: `"h1"`
    /// (default, plain HTTP/1.1) or `"h2"` (HTTP/2 in prior-knowledge
    /// mode, i.e. h2c without ALPN). Independent of what the inbound
    /// client speaks.
    pub backend_proto: Option<String>,
    /// Apply the fallback to the TCP listener (HTTP/1.1 + HTTP/2).
    /// Default `true`. Set `false` when only the HTTP/3 listener
    /// should masquerade.
    pub apply_to_h1: Option<bool>,
    /// Apply the fallback to the HTTP/3 listener (UDP/QUIC). Default
    /// `false` so that upgrading the binary does not silently start
    /// forwarding QUIC traffic to a backend that was only set up for
    /// TCP. Requires `[server.h3]`; rejects `proxy_protocol = "v1"`.
    pub apply_to_h3: Option<bool>,
}

/// `[sni_fallback]` block. When present and the inbound TCP listener
/// terminates TLS, peeks the ClientHello before handshake: if the SNI
/// matches `match_sni`, terminates locally as before; otherwise splices
/// the raw TCP stream (including the captured ClientHello) to a backend
/// chosen by SNI. Sister of `[http_fallback]` — different OSI layer,
/// same camouflage idea.
///
/// Two mutually exclusive formats:
///
/// **Single-backend (legacy):** `backend` at section level, all foreign
/// SNIs go to one upstream.
///
/// **Multi-backend:** omit `backend`; add one or more
/// `[[sni_fallback.backends]]` tables, each with its own `backend` and
/// `match_sni`. A backend whose `match_sni` is absent or empty is a
/// catch-all and must be the last entry.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SniFallbackSection {
    /// Single-backend mode: `host:port` of the upstream. Mutually
    /// exclusive with `backends`.
    pub backend: Option<String>,
    /// Whitelist of SNIs treated as "ours" (handled locally). Each
    /// entry is matched case-insensitively; `*.` prefix matches one
    /// label to the left (nginx-style). Required.
    pub match_sni: Option<Vec<String>>,
    /// What to do for connections that arrive without an SNI extension.
    /// Default `false` — splice to the backend.
    pub allow_no_sni: Option<bool>,
    /// Single-backend mode: wrap the upstream TCP connection in a
    /// HAProxy PROXY-protocol header. Default: disabled.
    pub proxy_protocol: Option<String>,
    /// Maximum bytes to buffer while waiting for a parseable
    /// ClientHello. Anything larger is treated as a malformed TLS
    /// handshake and the connection is closed. Default 8192.
    pub max_client_hello_bytes: Option<usize>,
    /// Multi-backend mode: ordered list of backends. Mutually exclusive
    /// with `backend`. First match wins; a catch-all (no `match_sni`)
    /// must be last.
    pub backends: Option<Vec<SniBackendSection>>,
}

/// One entry in `[[sni_fallback.backends]]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SniBackendSection {
    /// `host:port` of this backend.
    pub backend: String,
    /// SNIs routed to this backend. Absent or empty = catch-all.
    pub match_sni: Option<Vec<String>>,
    /// HAProxy PROXY-protocol version for this backend. Default: disabled.
    pub proxy_protocol: Option<String>,
}

/// `[session_resumption]` block. All fields are optional; absence keeps
/// the feature disabled. See `docs/SESSION-RESUMPTION.md` for semantics
/// and recommended values.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionResumptionSection {
    pub enabled: Option<bool>,
    pub orphan_ttl_tcp_secs: Option<u64>,
    pub orphan_ttl_udp_secs: Option<u64>,
    pub orphan_per_user_cap: Option<usize>,
    pub orphan_global_cap: Option<usize>,
    /// Per-session downlink ring buffer capacity for the v2 Symmetric
    /// Downlink Replay protocol. `0` (the default) disables v2
    /// server-side: the capability is never echoed and ring buffers
    /// are never allocated. See `docs/SESSION-RESUMPTION.md`
    /// § Symmetric Downlink Replay (v2).
    pub downlink_buffer_bytes: Option<usize>,
}

/// `[padding]` block. Adaptive application-layer padding on the WS / XHTTP
/// carriers: each Shadowsocks chunk is wrapped in a length-delimited frame so
/// the bytes handed to the outer TLS record layer stop tracking the payload
/// size, blunting record-size ("proxy-inside-TLS") fingerprinting. Absent or
/// `enabled = false` keeps the wire byte-for-byte identical to the unpadded
/// carrier. Config-synchronised, like `[session_resumption]`: there is no
/// on-wire capability bit, so both ends must enable it together.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PaddingSection {
    /// Master switch. Default `false`.
    pub enabled: Option<bool>,
    /// Minimum pad bytes drawn per frame. Default 0.
    pub min_bytes: Option<u16>,
    /// Maximum pad bytes drawn per frame (clamped up to `min_bytes` if
    /// smaller). Default 256 — the light profile: breaks exact size
    /// correlation at minimal traffic overhead.
    pub max_bytes: Option<u16>,
    /// Emit cover frames (pad-only, `real_len = 0`) while the connection is
    /// idle, so silence does not leak timing. Default `false`.
    pub cover: Option<bool>,
    /// Idle gap before a cover frame, randomised in
    /// `[cover_jitter_min_ms, cover_jitter_max_ms]`. Defaults 250 / 1500.
    pub cover_jitter_min_ms: Option<u64>,
    pub cover_jitter_max_ms: Option<u64>,
    /// Carrier paths to pad. Only connections whose matched path is listed
    /// are padded; third-party clients (Happ, Outline, xray, sing-box) on
    /// other paths keep the plain SS-over-WS/XHTTP wire. Required (non-empty)
    /// when `enabled`.
    pub paths: Option<Vec<String>>,
}

pub(super) fn load_file_config(path: &Path) -> Result<FileConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    toml::from_str(&contents)
        .with_context(|| format!("failed to parse config file {}", path.display()))
}

pub(super) fn default_config_path_if_exists() -> Option<PathBuf> {
    let path = PathBuf::from("config.toml");
    if path.exists() { Some(path) } else { None }
}

#[cfg(test)]
#[path = "tests/file.rs"]
mod tests;
