//! End-to-end coverage for the `[http_fallback]` reverse-proxy.
//!
//! These tests stand up a real upstream (either an axum echo-app or a
//! raw `TcpListener` for the PROXY-protocol assertions), point the
//! production `build_app` at it, and dial through the fallback handler
//! over a regular `hyper-util` client.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result};
use axum::{
    Router,
    extract::Request,
    http::{HeaderMap, Method, StatusCode, header},
    response::IntoResponse,
    routing::any,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::super::transport::HttpFallbackContext;
use super::super::{DnsCache, build_app, build_user_routes};
use super::{build_test_state, sample_config};
use crate::config::{HttpFallbackConfig, ProxyProtocolVersion};
use crate::metrics::Metrics;

/// Snapshot of one upstream request, captured by the echo handler so
/// the test can assert on what the proxy actually sent.
#[derive(Clone, Debug)]
struct CapturedRequest {
    method: Method,
    uri: String,
    headers: HeaderMap,
    body: Bytes,
}

/// Spawns a minimal axum upstream that records the next incoming
/// request through `tx` and returns a fixed response. Returns the
/// listening address and the receiver side of the channel.
async fn spawn_echo_upstream(
    response_status: StatusCode,
    response_headers: Vec<(&'static str, &'static str)>,
    response_body: &'static str,
) -> Result<(SocketAddr, oneshot::Receiver<CapturedRequest>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel::<CapturedRequest>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let app: Router = Router::new().fallback(any(move |request: Request| {
        let tx = Arc::clone(&tx);
        let response_headers = response_headers.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body_bytes = body.collect().await.unwrap().to_bytes();
            if let Some(tx) = tx.lock().await.take() {
                let _ = tx.send(CapturedRequest {
                    method: parts.method.clone(),
                    uri: parts.uri.to_string(),
                    headers: parts.headers.clone(),
                    body: body_bytes,
                });
            }
            let mut builder = axum::http::Response::builder().status(response_status);
            for (k, v) in &response_headers {
                builder = builder.header(*k, *v);
            }
            builder.body(axum::body::Body::from(response_body)).unwrap()
        }
    }));

    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    Ok((addr, rx))
}

fn fallback_ctx_for(
    upstream: SocketAddr,
    inbound_listen: SocketAddr,
    proxy_protocol: Option<ProxyProtocolVersion>,
) -> Arc<HttpFallbackContext> {
    Arc::new(HttpFallbackContext {
        config: Arc::new(HttpFallbackConfig {
            backend_scheme: "http".into(),
            backend_authority: upstream.to_string(),
            backend_host: upstream.ip().to_string(),
            backend_port: upstream.port(),
            request_timeout_secs: 5,
            add_x_forwarded_for: true,
            add_x_forwarded_proto: true,
            add_x_forwarded_host: true,
            proxy_protocol,
        }),
        inbound_listen,
        inbound_tls: false,
    })
}

#[tokio::test]
async fn http_fallback_proxies_unmatched_requests_to_upstream() -> Result<()> {
    let (upstream_addr, rx) = spawn_echo_upstream(
        StatusCode::OK,
        vec![("content-type", "text/plain"), ("x-upstream-marker", "yes")],
        "hello-from-upstream",
    )
    .await?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let config = sample_config(addr);
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let fallback = fallback_ctx_for(upstream_addr, addr, None);
    let app = build_app(routes, services, auth, Some(fallback));
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let response = client
        .request(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/anything?x=1"))
                .header("x-marker", "passthrough")
                // Hop-by-hop headers — must NOT propagate.
                .header(header::CONNECTION, "keep-alive, x-custom-hop")
                .header("x-custom-hop", "should-be-stripped")
                .body(Empty::<Bytes>::new())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("x-upstream-marker").unwrap(), "yes");

    let body = response.into_body().collect().await?.to_bytes();
    assert_eq!(body.as_ref(), b"hello-from-upstream");

    let captured = rx.await?;
    assert_eq!(captured.method, Method::GET);
    assert!(
        captured.uri.contains("/anything"),
        "unexpected upstream uri: {}",
        captured.uri
    );
    assert!(
        captured.uri.contains("x=1"),
        "query string lost: {}",
        captured.uri
    );
    assert_eq!(captured.headers.get("x-marker").unwrap(), "passthrough");
    assert_eq!(
        captured.headers.get(header::HOST).unwrap().to_str()?,
        upstream_addr.to_string()
    );
    let xff = captured
        .headers
        .get("x-forwarded-for")
        .context("missing X-Forwarded-For")?
        .to_str()?;
    assert!(xff.contains("127.0.0.1"), "unexpected xff: {xff}");
    assert_eq!(
        captured.headers.get("x-forwarded-proto").unwrap().to_str()?,
        "http"
    );
    assert!(
        captured.headers.get("x-forwarded-host").is_some(),
        "missing x-forwarded-host"
    );
    assert!(
        captured.headers.get("connection").is_none(),
        "hop-by-hop Connection leaked"
    );
    assert!(
        captured.headers.get("x-custom-hop").is_none(),
        "Connection-listed token x-custom-hop leaked"
    );
    assert_eq!(captured.body.as_ref(), b"");

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn http_fallback_proxies_post_with_body() -> Result<()> {
    let (upstream_addr, rx) = spawn_echo_upstream(
        StatusCode::CREATED,
        vec![("content-type", "application/json")],
        "{\"ok\":true}",
    )
    .await?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let config = sample_config(addr);
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let fallback = fallback_ctx_for(upstream_addr, addr, None);
    let app = build_app(routes, services, auth, Some(fallback));
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let payload = b"{\"ping\":1}".to_vec();
    let response = client
        .request(
            axum::http::Request::builder()
                .method(Method::POST)
                .uri(format!("http://{addr}/api/echo"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(payload.clone())))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let captured = rx.await?;
    assert_eq!(captured.method, Method::POST);
    assert_eq!(captured.body.as_ref(), payload.as_slice());

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn http_fallback_disabled_returns_404_for_unknown_path() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let config = sample_config(addr);
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth, None);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let response = client
        .request(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/anything"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    server.abort();
    let _ = server.await;
    Ok(())
}

/// Raw-TCP upstream that captures the first ~256 bytes off the socket
/// so the test can assert on the PROXY-protocol header. Replies with
/// a minimal HTTP/1.1 response so hyper's client doesn't choke on a
/// half-open dialog and surface the failure as `BAD_GATEWAY`.
async fn spawn_proxy_protocol_capture()
-> Result<(SocketAddr, oneshot::Receiver<Vec<u8>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel::<Vec<u8>>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 1024];
            let mut total = 0usize;
            // Read until either we have enough or the stream goes
            // quiet for ~200 ms so the PROXY header and the request
            // line that follows it both end up in `captured`, even
            // when the kernel splits them across two reads.
            loop {
                let read = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    stream.read(&mut buf[total..]),
                )
                .await;
                match read {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        total += n;
                        if total >= 256 {
                            break;
                        }
                    },
                }
            }
            buf.truncate(total);
            if let Some(tx) = tx.lock().await.take() {
                let _ = tx.send(buf);
            }
            let _ = stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = stream.shutdown().await;
        }
    });
    Ok((addr, rx))
}

#[tokio::test]
async fn http_fallback_emits_proxy_protocol_v1_header() -> Result<()> {
    let (upstream_addr, rx) = spawn_proxy_protocol_capture().await?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let config = sample_config(addr);
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let fallback =
        fallback_ctx_for(upstream_addr, addr, Some(ProxyProtocolVersion::V1));
    let app = build_app(routes, services, auth, Some(fallback));
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let response = client
        .request(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/anything"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let captured = rx.await?;
    let header_str = std::str::from_utf8(&captured)?;
    assert!(
        header_str.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "unexpected PROXY v1 header: {header_str:?}"
    );
    assert!(
        header_str.contains(&format!(" {}\r\n", addr.port())),
        "missing inbound listener port {} in header: {header_str:?}",
        addr.port()
    );
    let crlf = captured.iter().position(|b| *b == b'\n').unwrap();
    let after_header = &captured[crlf + 1..];
    assert!(
        after_header.starts_with(b"GET /anything"),
        "PROXY v1 header was not followed by the HTTP request: \
         {after_header:?}"
    );

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn http_fallback_emits_proxy_protocol_v2_header() -> Result<()> {
    let (upstream_addr, rx) = spawn_proxy_protocol_capture().await?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let config = sample_config(addr);
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let fallback =
        fallback_ctx_for(upstream_addr, addr, Some(ProxyProtocolVersion::V2));
    let app = build_app(routes, services, auth, Some(fallback));
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();
    let response = client
        .request(
            axum::http::Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/anything"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let captured = rx.await?;
    // 12-byte signature + 4-byte ver/cmd/family/len + 12 bytes for TCP4 src/dst.
    assert!(captured.len() >= 28, "v2 header truncated: {captured:?}");
    assert_eq!(
        &captured[..12],
        &[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]
    );
    assert_eq!(captured[12], 0x21, "expected ver=2 cmd=PROXY");
    assert_eq!(captured[13], 0x11, "expected AF_INET + STREAM");
    let addr_len = u16::from_be_bytes([captured[14], captured[15]]);
    assert_eq!(addr_len, 12, "expected TCP4 address block length");
    // src IPv4 (4) + dst IPv4 (4) + src port (2) + dst port (2)
    assert_eq!(&captured[16..20], &[127, 0, 0, 1]);
    assert_eq!(&captured[20..24], &[127, 0, 0, 1]);
    let dst_port = u16::from_be_bytes([captured[26], captured[27]]);
    assert_eq!(dst_port, addr.port(), "dst port should match listener");
    let after_header = &captured[28..];
    assert!(
        after_header.starts_with(b"GET /anything"),
        "PROXY v2 header was not followed by the HTTP request: {after_header:?}"
    );

    server.abort();
    let _ = server.await;
    Ok(())
}

// `fallback_ctx_for` carries `inbound_tls = false`, so the
// X-Forwarded-Proto assertion above already covers the http variant.
// Coverage of `https` would need the TLS listener path, which is not
// reachable through `serve_listener`; left out of this MVP suite.
#[allow(dead_code)]
fn _ensure_into_response_compiles() -> axum::response::Response {
    StatusCode::OK.into_response()
}
