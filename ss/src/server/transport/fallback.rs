//! HTTP-level fallback reverse-proxy. When `[http_fallback]` is set,
//! requests that miss every websocket / xhttp / metrics / control
//! route are forwarded to an upstream backend (haproxy / nginx /
//! caddy) instead of returning 404. Lets the listener masquerade as a
//! regular web service sitting behind an existing HTTP front-end.
//!
//! Implementation notes:
//! - Hop-by-hop headers (RFC 7230 §6.1) are stripped on both
//!   directions; values listed in `Connection:` are stripped too.
//! - `X-Forwarded-{For,Proto,Host}` are appended/set per config.
//! - `Host` is replaced with the backend authority so that virtual
//!   hosts on the backend resolve as if the request originated there
//!   (mirrors nginx's `proxy_set_header Host $proxy_host;`).
//! - One TCP connection per request via low-level `hyper::client::conn`.
//!   Fallback traffic is the rare-path; pooling is not worth the extra
//!   wiring through a custom hyper connector that would also need to
//!   carry per-request PROXY-protocol metadata.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{ConnectInfo, OriginalUri, Request, State},
    http::{
        self, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, Version, header,
        request::Parts,
    },
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use tokio::{io::AsyncWriteExt, net::TcpStream, time::Duration};
use tracing::{debug, warn};

use crate::config::HttpFallbackConfig;

use super::super::auth::build_not_found_response;
use super::super::state::AppState;
use super::proxy_protocol::encode_proxy_protocol;

/// Per-process state for the fallback handler. Built once at startup,
/// shared by every fallback request via `AppState`.
#[derive(Clone)]
pub(in crate::server) struct HttpFallbackContext {
    pub(in crate::server) config: Arc<HttpFallbackConfig>,
    /// Address the inbound listener is bound to. Used as the
    /// destination for PROXY-protocol headers. `0.0.0.0` / `[::]`
    /// degrade to UNSPEC (v2) / UNKNOWN (v1) since we do not learn
    /// the per-stream local address with the current `axum::serve`
    /// wiring.
    pub(in crate::server) inbound_listen: SocketAddr,
    /// `true` when the inbound listener terminates TLS — drives the
    /// value of `X-Forwarded-Proto`.
    pub(in crate::server) inbound_tls: bool,
}

pub(in crate::server) async fn http_fallback_handler(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> Response {
    let Some(ctx) = state.http_fallback.as_ref() else {
        return build_not_found_response(Body::empty()).into_response();
    };
    let timeout = Duration::from_secs(ctx.config.request_timeout_secs);
    let ctx = Arc::clone(ctx);
    match tokio::time::timeout(timeout, proxy_to_backend(ctx, peer_addr, uri, request)).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            warn!(?error, "http fallback proxy failed");
            (StatusCode::BAD_GATEWAY, Body::empty()).into_response()
        },
        Err(_) => {
            warn!(timeout_secs = timeout.as_secs(), "http fallback proxy timed out");
            (StatusCode::GATEWAY_TIMEOUT, Body::empty()).into_response()
        },
    }
}

async fn proxy_to_backend(
    ctx: Arc<HttpFallbackContext>,
    peer_addr: SocketAddr,
    original_uri: Uri,
    request: Request,
) -> Result<Response> {
    let (parts, body) = request.into_parts();
    let upstream_req = build_upstream_request(&ctx, peer_addr, &original_uri, &parts, body)?;

    let stream = TcpStream::connect(ctx.config.backend_authority.as_str())
        .await
        .with_context(|| {
            format!("failed to connect to {}", ctx.config.backend_authority.as_str())
        })?;

    let stream = if let Some(version) = ctx.config.proxy_protocol {
        let mut header = Vec::with_capacity(64);
        encode_proxy_protocol(&mut header, version, peer_addr, ctx.inbound_listen);
        let mut stream = stream;
        stream
            .write_all(&header)
            .await
            .context("failed to write PROXY-protocol header to upstream")?;
        stream
    } else {
        stream
    };

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .handshake::<_, Body>(TokioIo::new(stream))
        .await
        .context("failed to handshake with upstream")?;

    let conn_task = tokio::spawn(async move {
        if let Err(error) = conn.await {
            debug!(?error, "http fallback upstream connection ended with error");
        }
    });

    let response = sender
        .send_request(upstream_req)
        .await
        .context("failed to send request to upstream")?;
    drop(sender);
    let (resp_parts, resp_body) = response.into_parts();
    // Surface any framing-level error from the connection task by
    // letting it run to completion; the body's read side joins it
    // implicitly via the channel.
    drop(conn_task);

    let mut builder = Response::builder().status(resp_parts.status);
    let resp_headers = builder.headers_mut().expect("response builder ok");
    let resp_skip = collect_connection_tokens(&resp_parts.headers);
    for (name, value) in resp_parts.headers.iter() {
        if is_hop_by_hop(name) || resp_skip.iter().any(|skip| skip == name.as_str()) {
            continue;
        }
        resp_headers.append(name.clone(), value.clone());
    }
    let body = Body::new(resp_body.map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }));
    builder.body(body).context("failed to assemble fallback response")
}

fn build_upstream_request(
    ctx: &HttpFallbackContext,
    peer_addr: SocketAddr,
    original_uri: &Uri,
    parts: &Parts,
    body: Body,
) -> Result<http::Request<Body>> {
    let path_and_query = original_uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
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
        let proto = if ctx.inbound_tls { "https" } else { "http" };
        dest_headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static(proto),
        );
    }
    if ctx.config.add_x_forwarded_host {
        if let Some(host) = original_host.as_deref()
            && let Ok(value) = HeaderValue::from_str(host)
        {
            dest_headers.insert(HeaderName::from_static("x-forwarded-host"), value);
        }
    }

    req.body(body).context("failed to assemble upstream request")
}

fn append_xff(headers: &mut HeaderMap, peer_addr: SocketAddr) {
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
fn is_hop_by_hop(name: &HeaderName) -> bool {
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
fn collect_connection_tokens(headers: &HeaderMap) -> Vec<String> {
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

