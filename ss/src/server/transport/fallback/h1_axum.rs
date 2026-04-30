//! HTTP/1.1 + HTTP/2 inbound adapter for the fallback reverse-proxy,
//! wired through the axum router on the TCP listener. When
//! `[http_fallback]` is set, requests that miss every websocket /
//! xhttp / metrics / control route are forwarded to an upstream
//! backend (haproxy / nginx / caddy) instead of returning 404. Lets
//! the listener masquerade as a regular web service sitting behind
//! an existing HTTP front-end.
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
    http::{self, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::Duration};
use tracing::{debug, warn};

use super::shared::{
    HttpFallbackContext, build_upstream_parts, collect_connection_tokens, is_hop_by_hop,
};
use crate::config::BackendProto;
use crate::server::auth::build_not_found_response;
use crate::server::state::AppState;
use crate::server::transport::proxy_protocol::{PpTransport, encode_proxy_protocol};

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
    let (parts_in, body) = request.into_parts();
    let upstream_parts = build_upstream_parts(&ctx, peer_addr, &original_uri, &parts_in)?;
    let upstream_req = http::Request::from_parts(upstream_parts, body);

    let stream = TcpStream::connect(ctx.config.backend_authority.as_str())
        .await
        .with_context(|| {
            format!("failed to connect to {}", ctx.config.backend_authority.as_str())
        })?;

    let stream = if let Some(version) = ctx.config.proxy_protocol {
        let mut header = Vec::with_capacity(64);
        encode_proxy_protocol(
            &mut header,
            version,
            peer_addr,
            ctx.inbound_listen,
            PpTransport::Stream,
        );
        let mut stream = stream;
        stream
            .write_all(&header)
            .await
            .context("failed to write PROXY-protocol header to upstream")?;
        stream
    } else {
        stream
    };

    // Two builders, one shape: handshake → spawn the connection
    // driver task → send the request and hand back the response.
    // The driver keeps running after `sender` is dropped; the
    // response body channel keeps working as long as the task is
    // alive. We discard the JoinHandle on purpose — the task ends
    // when the body is consumed and the connection closes.
    let response = match ctx.config.backend_proto {
        BackendProto::H1 => {
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .handshake::<_, Body>(TokioIo::new(stream))
                .await
                .context("failed to handshake with upstream over HTTP/1.1")?;
            tokio::spawn(async move {
                if let Err(error) = conn.await {
                    debug!(?error, "h1 upstream connection ended with error");
                }
            });
            sender
                .send_request(upstream_req)
                .await
                .context("failed to send request to upstream over HTTP/1.1")?
        },
        BackendProto::H2 => {
            // Prior-knowledge h2c: no ALPN, no Upgrade. Upstream MUST
            // be configured to expect h2 directly on this listen port.
            let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Body>(TokioIo::new(stream))
                .await
                .context("failed to handshake with upstream over HTTP/2")?;
            tokio::spawn(async move {
                if let Err(error) = conn.await {
                    debug!(?error, "h2 upstream connection ended with error");
                }
            });
            sender
                .send_request(upstream_req)
                .await
                .context("failed to send request to upstream over HTTP/2")?
        },
    };
    let (resp_parts, resp_body) = response.into_parts();

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
