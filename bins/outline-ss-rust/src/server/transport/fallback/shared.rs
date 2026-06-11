//! Transport-agnostic plumbing for the fallback reverse-proxy:
//! header rewriting (hop-by-hop, `Connection:`-listed, `Host`,
//! `X-Forwarded-*`) and the per-process state shared by every
//! fallback request. Lives apart from the per-listener adapters so
//! the wire-format details stay in one place when more inbound
//! protocols (HTTP/3) get wired in.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::http::{self, HeaderMap, HeaderName, HeaderValue, Uri, Version, header, request::Parts};

use crate::config::HttpFallbackConfig;

/// Per-process state for the fallback handler. Built once at startup,
/// shared by every fallback request via `AppState` (h1 path) and
/// `H3ConnectionCtx` (h3 path).
#[derive(Clone)]
pub(in crate::server) struct HttpFallbackContext {
    pub(in crate::server) config: Arc<HttpFallbackConfig>,
    /// Bind addr of the TCP listener. `Some` when `apply_to_h1` is
    /// on; used as the destination in PROXY-protocol headers emitted
    /// by the h1/h2 adapter. `0.0.0.0` / `[::]` degrade to UNSPEC
    /// (v2) / UNKNOWN (v1) since we do not learn the per-stream
    /// local address with the current `axum::serve` wiring.
    pub(in crate::server) tcp_inbound_listen: Option<SocketAddr>,
    /// Bind addr of the HTTP/3 listener. `Some` when `apply_to_h3`
    /// is on; used as the destination in PROXY-protocol headers
    /// emitted by the h3 adapter (transport `Dgram`).
    pub(in crate::server) h3_inbound_listen: Option<SocketAddr>,
    /// `true` when the TCP inbound listener terminates TLS — drives
    /// the value of `X-Forwarded-Proto` for the h1 adapter. The h3
    /// adapter always reports `https` since QUIC is encrypted.
    pub(in crate::server) inbound_tls: bool,
}

/// Builds the upstream `Parts` (method, URI, headers) without a
/// body. Callers attach their own body type — `axum::body::Body` for
/// the TCP listener, an `h3::server::RequestStream` adapter for the
/// HTTP/3 listener — so this stays transport-agnostic.
///
/// `is_secure_inbound` drives `X-Forwarded-Proto` when the toggle is
/// on. The h1 adapter passes `ctx.inbound_tls`; the h3 adapter
/// passes `true` unconditionally because QUIC is always encrypted.
pub(super) fn build_upstream_parts(
    ctx: &HttpFallbackContext,
    peer_addr: SocketAddr,
    original_uri: &Uri,
    parts: &Parts,
    is_secure_inbound: bool,
) -> Result<Parts> {
    let path_and_query = original_uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    // Origin-form (just `/path?query`) — backends like nginx/haproxy
    // typically reject the absolute-form `http://host/path` that
    // proxies use to address each other, so we mimic what curl /
    // browsers send to a regular origin server.
    let upstream_uri: Uri = path_and_query
        .parse()
        .with_context(|| format!("failed to build upstream URI from {path_and_query:?}"))?;

    let mut req = http::Request::builder()
        .method(parts.method.clone())
        .uri(upstream_uri)
        .version(Version::HTTP_11);

    let original_host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let req_skip = collect_connection_tokens(&parts.headers);
    let dest_headers = req.headers_mut().expect("request builder ok");
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name)
            || req_skip.iter().any(|skip| skip == name.as_str())
            || name == header::HOST
        {
            continue;
        }
        dest_headers.append(name.clone(), value.clone());
    }

    let host_value = HeaderValue::from_str(ctx.config.backend_authority.as_str())
        .context("backend authority is not a valid Host header value")?;
    dest_headers.insert(header::HOST, host_value);

    if ctx.config.add_x_forwarded_for {
        append_xff(dest_headers, peer_addr);
    }
    if ctx.config.add_x_forwarded_proto {
        let proto = if is_secure_inbound { "https" } else { "http" };
        dest_headers
            .insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static(proto));
    }
    if ctx.config.add_x_forwarded_host {
        if let Some(host) = original_host.as_deref()
            && let Ok(value) = HeaderValue::from_str(host)
        {
            dest_headers.insert(HeaderName::from_static("x-forwarded-host"), value);
        }
    }

    let request = req.body(()).context("failed to assemble upstream request parts")?;
    Ok(request.into_parts().0)
}

pub(super) fn append_xff(headers: &mut HeaderMap, peer_addr: SocketAddr) {
    let peer = peer_addr.ip().to_string();
    let new_value = match headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.is_empty() => format!("{existing}, {peer}"),
        _ => peer,
    };
    if let Ok(value) = HeaderValue::from_str(&new_value) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), value);
    }
}

/// Hop-by-hop headers per RFC 7230 §6.1. These never propagate across
/// a proxy; they describe the immediate connection only.
pub(super) fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Anything listed in the `Connection:` header is also hop-by-hop —
/// returns those tokens lowercased so they can be matched against
/// header names.
pub(super) fn collect_connection_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all(header::CONNECTION).iter() {
        let Ok(text) = value.to_str() else { continue };
        for token in text.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                out.push(token.to_ascii_lowercase());
            }
        }
    }
    out
}
