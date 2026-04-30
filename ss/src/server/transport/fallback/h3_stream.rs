//! HTTP/3 inbound adapter for the fallback reverse-proxy. When
//! `[http_fallback]` is set with `apply_to_h3 = true`, requests on
//! the QUIC listener that did not match an XHTTP / WS-over-h3 path
//! and are not the `/` auth-root challenge are forwarded to the
//! configured upstream backend, exactly like the h1 listener does.
//!
//! Implementation notes:
//! - Request body is buffered before forwarding. Fallback traffic is
//!   typically small (probes, idle pings, GETs from active scanners
//!   touching `/`) — splitting the `RequestStream` and streaming both
//!   halves concurrently would buy throughput on a path that is not
//!   on the hot path. If anyone ever points high-volume uploads at
//!   the fallback we can revisit.
//! - Response body is *streamed* — `hyper::body::Incoming` is pumped
//!   chunk-by-chunk into `h3::server::RequestStream::send_data`, so a
//!   masquerade backend serving a large file or an SSE feed flows
//!   through without the server holding the whole response in RAM.
//! - PROXY-protocol uses `PpTransport::Dgram` because the inbound is
//!   QUIC/UDP. v1 is forbidden at config-load time (RFC 9000 / v1
//!   spec only define TCP), so by the time we get here we always
//!   emit v2.
//! - `X-Forwarded-Proto` is always `https` — QUIC is encrypted by
//!   spec, there is no "plain h3" listener.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use axum::http;
use bytes::{Buf, Bytes, BytesMut};
use h3::server::RequestStream;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::Duration};
use tracing::{debug, warn};

use super::shared::{
    HttpFallbackContext, build_upstream_parts, collect_connection_tokens, is_hop_by_hop,
};
use crate::config::BackendProto;
use crate::server::transport::proxy_protocol::{PpTransport, encode_proxy_protocol};

type H3Stream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

pub(in crate::server) async fn h3_fallback_handle(
    request: http::Request<()>,
    stream: H3Stream,
    ctx: Arc<HttpFallbackContext>,
    peer_addr: SocketAddr,
) -> Result<()> {
    let timeout = Duration::from_secs(ctx.config.request_timeout_secs);
    match tokio::time::timeout(timeout, proxy_h3_to_backend(request, stream, ctx, peer_addr)).await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            warn!(?error, "h3 fallback proxy failed");
            Err(error)
        },
        Err(_) => {
            // Caller already saw the timeout via the warn! emitted in
            // the timeout branch; the stream is dropped, which closes
            // the QUIC bidi cleanly.
            warn!(timeout_secs = timeout.as_secs(), "h3 fallback proxy timed out");
            Ok(())
        },
    }
}

async fn proxy_h3_to_backend(
    request: http::Request<()>,
    mut stream: H3Stream,
    ctx: Arc<HttpFallbackContext>,
    peer_addr: SocketAddr,
) -> Result<()> {
    // Drain the request body up-front. `recv_data` returns `impl Buf`
    // chunks that we copy into a single contiguous `Bytes` so hyper's
    // client builder can take a `Full<Bytes>` body.
    let mut body_buf = BytesMut::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .context("failed to read HTTP/3 request body")?
    {
        // `Buf::chunk()` is a borrow of the current contiguous slice;
        // for h3 chunks this is the full payload, but we loop on
        // `has_remaining` so the code stays correct for any future
        // implementation that returns multiple slices per chunk.
        while chunk.has_remaining() {
            let slice = chunk.chunk();
            body_buf.extend_from_slice(slice);
            let len = slice.len();
            chunk.advance(len);
        }
    }
    let request_trailers = stream
        .recv_trailers()
        .await
        .context("failed to read HTTP/3 request trailers")?;

    let original_uri = request.uri().clone();
    let (parts_in, _empty_body) = request.into_parts();
    let mut upstream_parts =
        build_upstream_parts(&ctx, peer_addr, &original_uri, &parts_in, true)?;

    // h3 lets the request carry trailers; relay them on the upstream
    // request via the `Trailer` HTTP header so an h2 backend that
    // tracks the indication can mirror it back. The actual trailer
    // values are merged into the body's trailing frame below — but
    // hyper http1 does not surface request trailers in the wire form
    // anyway, so this is effectively a no-op for `backend_proto = h1`.
    if let Some(trailers) = request_trailers.as_ref() {
        for (name, value) in trailers.iter() {
            upstream_parts.headers.append(name.clone(), value.clone());
        }
    }

    let upstream_req = http::Request::from_parts(upstream_parts, Full::new(body_buf.freeze()));

    let tcp = TcpStream::connect(ctx.config.backend_authority.as_str())
        .await
        .with_context(|| {
            format!("failed to connect to {}", ctx.config.backend_authority.as_str())
        })?;
    let tcp = if let Some(version) = ctx.config.proxy_protocol {
        // Validation forbids v1 + apply_to_h3 — by here we always emit
        // v2 with `Dgram` transport so the backend can tell the
        // origin was UDP/QUIC.
        let dst = ctx
            .h3_inbound_listen
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let mut header = Vec::with_capacity(64);
        encode_proxy_protocol(&mut header, version, peer_addr, dst, PpTransport::Dgram);
        let mut tcp = tcp;
        tcp.write_all(&header)
            .await
            .context("failed to write PROXY-protocol header to upstream")?;
        tcp
    } else {
        tcp
    };

    // Same dispatch as the h1 adapter — the only difference is the
    // request body type. The conn-driver task is spawned and then
    // forgotten; it lives until the response body is fully consumed.
    let response = match ctx.config.backend_proto {
        BackendProto::H1 => {
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .handshake::<_, Full<Bytes>>(TokioIo::new(tcp))
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
            let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake::<_, Full<Bytes>>(TokioIo::new(tcp))
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

    let (resp_parts, mut resp_body) = response.into_parts();

    // Build the h3 response (headers only — body is streamed below).
    let mut response_only_headers = http::Response::builder().status(resp_parts.status);
    let dest_headers = response_only_headers
        .headers_mut()
        .expect("response builder ok");
    let resp_skip = collect_connection_tokens(&resp_parts.headers);
    for (name, value) in resp_parts.headers.iter() {
        if is_hop_by_hop(name) || resp_skip.iter().any(|skip| skip == name.as_str()) {
            continue;
        }
        dest_headers.append(name.clone(), value.clone());
    }
    let response_meta = response_only_headers
        .body(())
        .context("failed to assemble HTTP/3 response head")?;
    stream
        .send_response(response_meta)
        .await
        .context("failed to send HTTP/3 response head")?;

    // Stream the upstream response body chunk-by-chunk into the h3
    // RequestStream. Trailers come last — `send_trailers` finishes
    // the body stream, but `finish()` is what closes the QUIC stream
    // cleanly; per h3 docs both must be called.
    let mut response_trailers: Option<http::HeaderMap> = None;
    while let Some(frame) = resp_body.frame().await {
        let frame = frame.context("upstream response body errored")?;
        match frame.into_data() {
            Ok(data) => {
                if !data.is_empty() {
                    stream
                        .send_data(data)
                        .await
                        .context("failed to forward upstream body chunk to h3")?;
                }
            },
            Err(non_data) => {
                if let Ok(trailers) = non_data.into_trailers() {
                    response_trailers = Some(trailers);
                }
            },
        }
    }
    if let Some(trailers) = response_trailers {
        // Strip hop-by-hop trailers symmetrically to headers — most
        // are RFC 7230 §6.1 names but a future upstream could surface
        // novel ones.
        let mut filtered = http::HeaderMap::with_capacity(trailers.len());
        for (name, value) in trailers.iter() {
            if !is_hop_by_hop(name) {
                filtered.append(name.clone(), value.clone());
            }
        }
        if !filtered.is_empty() {
            stream
                .send_trailers(filtered)
                .await
                .context("failed to send HTTP/3 trailers")?;
        }
    }
    stream
        .finish()
        .await
        .context("failed to finalize HTTP/3 response stream")?;
    Ok(())
}
