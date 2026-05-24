use anyhow::Result;

use super::file::HttpFallbackSection;

/// Resolved `[http_fallback]` block. All fields are concrete (defaults
/// applied). The reverse-proxy is opt-in: when this is `None` the
/// listener returns 404 for unmatched paths, exactly as before.
#[derive(Debug, Clone)]
pub struct HttpFallbackConfig {
    /// `host:port` of the upstream backend. Scheme is fixed to `http`
    /// in the MVP — TLS to the backend is intentionally out of scope
    /// (the backend is expected to live on loopback or a trusted
    /// private network).
    pub backend_authority: String,
    /// Per-request timeout: connect + receive headers + receive body.
    pub request_timeout_secs: u64,
    pub add_x_forwarded_for: bool,
    pub add_x_forwarded_proto: bool,
    pub add_x_forwarded_host: bool,
    /// PROXY-protocol version to prepend to the upstream TCP stream
    /// (`None` to disable).
    pub proxy_protocol: Option<ProxyProtocolVersion>,
    /// HTTP version we speak to the upstream backend. Independent of
    /// the inbound version — an h1 client can still be relayed to an
    /// h2 backend (e.g. a gRPC gateway) and vice versa. `H2` uses the
    /// prior-knowledge form (no ALPN) since the upstream is plain
    /// HTTP and assumed to be on a trusted private network or
    /// loopback.
    pub backend_proto: BackendProto,
    /// Apply the fallback to the TCP listener (HTTP/1.1 + HTTP/2 via
    /// ALPN). `true` by default — preserves the legacy behaviour for
    /// existing deployments.
    pub apply_to_h1: bool,
    /// Apply the fallback to the HTTP/3 listener (UDP/QUIC). `false`
    /// by default so that upgrading the binary does not silently
    /// start forwarding QUIC traffic to a backend the operator only
    /// configured for TCP. Requires `[server.h3]` to be set; v1
    /// PROXY-protocol is rejected when this is on (RFC has no UDP
    /// form for v1).
    pub apply_to_h3: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    V1,
    V2,
}

/// HTTP wire-version the fallback uses when talking to the upstream
/// backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendProto {
    /// HTTP/1.1 — the legacy default. Compatible with everything
    /// (nginx / haproxy / caddy default vhosts, plain web servers).
    #[default]
    H1,
    /// HTTP/2 in prior-knowledge mode (no ALPN, no upgrade). The
    /// upstream MUST be configured to accept h2c on the listen port
    /// (e.g. nginx `listen ... http2;` with an h2c-enabled module,
    /// envoy / caddy / a gRPC server).
    H2,
}

impl HttpFallbackConfig {
    pub(super) fn from_section(section: HttpFallbackSection) -> Result<Option<Self>> {
        let Some(backend_raw) =
            section.backend.map(|b| b.trim().to_owned()).filter(|b| !b.is_empty())
        else {
            // Section present but no `backend` set is treated as opt-out
            // so operators can keep the block in templates without
            // accidentally enabling the proxy.
            return Ok(None);
        };
        let url = backend_raw.parse::<hyper::Uri>().map_err(|error| {
            anyhow::anyhow!("invalid http_fallback.backend {backend_raw:?}: {error}")
        })?;
        let scheme = url
            .scheme_str()
            .ok_or_else(|| anyhow::anyhow!("http_fallback.backend must include a scheme"))?
            .to_ascii_lowercase();
        if scheme != "http" {
            anyhow::bail!(
                "http_fallback.backend scheme {scheme:?} is not supported (only http:// in MVP)"
            );
        }
        if url.path() != "" && url.path() != "/" {
            anyhow::bail!("http_fallback.backend must not include a path; got {:?}", url.path());
        }
        if url.query().is_some() {
            anyhow::bail!("http_fallback.backend must not include a query string");
        }
        let host = url
            .host()
            .ok_or_else(|| anyhow::anyhow!("http_fallback.backend has no host"))?
            .to_owned();
        let port = url.port_u16().unwrap_or(80);
        let authority = if url.port_u16().is_some() {
            format!("{host}:{port}")
        } else {
            format!("{host}:80")
        };
        let proxy_protocol = parse_proxy_protocol(
            section.proxy_protocol.as_deref(),
            "http_fallback.proxy_protocol",
        )?;
        let backend_proto = match section.backend_proto.as_deref().map(str::trim) {
            None | Some("") | Some("h1") => BackendProto::H1,
            Some("h2") => BackendProto::H2,
            Some(other) => {
                anyhow::bail!("http_fallback.backend_proto must be \"h1\" or \"h2\"; got {other:?}")
            },
        };
        let apply_to_h1 = section.apply_to_h1.unwrap_or(true);
        let apply_to_h3 = section.apply_to_h3.unwrap_or(false);
        if !apply_to_h1 && !apply_to_h3 {
            anyhow::bail!(
                "http_fallback has both apply_to_h1 and apply_to_h3 disabled — \
                 the section would be a no-op; remove it instead",
            );
        }
        if apply_to_h3 && matches!(proxy_protocol, Some(ProxyProtocolVersion::V1)) {
            anyhow::bail!(
                "http_fallback.proxy_protocol = \"v1\" is not compatible with \
                 apply_to_h3 = true (PROXY-protocol v1 has no UDP form on the \
                 wire); use \"v2\" or disable proxy_protocol",
            );
        }
        let request_timeout_secs = section.request_timeout_secs.unwrap_or(30);
        if request_timeout_secs == 0 {
            anyhow::bail!("http_fallback.request_timeout_secs must be > 0");
        }
        Ok(Some(Self {
            backend_authority: authority,
            request_timeout_secs,
            add_x_forwarded_for: section.add_x_forwarded_for.unwrap_or(true),
            add_x_forwarded_proto: section.add_x_forwarded_proto.unwrap_or(true),
            add_x_forwarded_host: section.add_x_forwarded_host.unwrap_or(true),
            proxy_protocol,
            backend_proto,
            apply_to_h1,
            apply_to_h3,
        }))
    }
}

pub(super) fn validate_authority(raw: &str, field: &str) -> Result<()> {
    if !raw.contains(':') {
        anyhow::bail!("{field} must be host:port (got {raw:?})");
    }
    Ok(())
}

pub(super) fn parse_proxy_protocol(
    raw: Option<&str>,
    field: &str,
) -> Result<Option<ProxyProtocolVersion>> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some("v1") => Ok(Some(ProxyProtocolVersion::V1)),
        Some("v2") => Ok(Some(ProxyProtocolVersion::V2)),
        Some(other) => anyhow::bail!("{field} must be \"v1\" or \"v2\"; got {other:?}"),
    }
}
