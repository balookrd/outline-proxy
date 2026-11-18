//! Integration tests for Stage 2 Caddy emulation on TCP/TLS.
//!
//! Verifies:
//! 1. Plaintext HTTP request sent to the HTTPS port returns Go's verbatim 400 Bad Request.
//! 2. Unmatched routes without a fallback return an empty 200 OK with `Server: Caddy`
//!    and `Alt-Svc: h3=":<port>"; ma=2592000`.
//! 3. HTTP/2 requests receive Caddy response headers and standard Go/Caddy behavior.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::super::bootstrap::serve_tcp_listener;
use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::super::{DnsCache, build_app};
use super::build_test_state;
use super::sni_fallback::{make_sample_config_with_tls, permissive_client_config, test_lock};
use crate::metrics::Metrics;

async fn spawn_tls_caddy_server(
    h3_port: Option<u16>,
) -> Result<(SocketAddr, Arc<Metrics>, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (mut config, cert_path, key_path) = make_sample_config_with_tls(addr)?;
    if let Some(port) = h3_port {
        config.h3_listen = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        config.h3_cert_path = Some(cert_path);
        config.h3_key_path = Some(key_path);
    }
    let metrics = Metrics::new(&config);
    let (routes, services, auth) = build_test_state(
        &config,
        Arc::clone(&metrics),
        NatTable::new(Duration::from_secs(300)),
        DnsCache::new(Duration::from_secs(30)),
        false,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth, None, None);
    let metrics_for_server = Arc::clone(&metrics);
    let server = tokio::spawn(async move {
        serve_tcp_listener(
            listener,
            app,
            Arc::new(config),
            None,
            metrics_for_server,
            ShutdownSignal::never(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    Ok((addr, metrics, server))
}

async fn tls_handshake(addr: SocketAddr, alpn: &[&[u8]]) -> Result<TlsStream<TcpStream>> {
    let mut config = permissive_client_config();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let tcp = TcpStream::connect(addr).await?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?, tcp)
        .await?;
    Ok(tls)
}

#[tokio::test]
async fn test_plaintext_http_on_tls_port_matches_go() -> Result<()> {
    let _serial = test_lock().lock().await;
    let (addr, metrics, server) = spawn_tls_caddy_server(None).await?;

    const EXPECTED_RESP: &[u8] =
        b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n";

    // 1. GET request
    {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
        let _ = stream.shutdown().await;
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut resp)).await??;
        assert_eq!(
            resp.as_slice(),
            EXPECTED_RESP,
            "GET on HTTPS port must return verbatim Go 400 error"
        );
    }

    // 2. POST request
    {
        let mut stream = TcpStream::connect(addr).await?;
        stream
            .write_all(
                b"POST /api/upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest",
            )
            .await?;
        let _ = stream.shutdown().await;
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut resp)).await??;
        assert_eq!(
            resp.as_slice(),
            EXPECTED_RESP,
            "POST on HTTPS port must return verbatim Go 400 error"
        );
    }

    // Verify metric recorded
    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains(r#"outline_ss_tls_handshake_failed_total{reason="http_on_https"}"#),
        "metrics must record http_on_https failures: {rendered}"
    );

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn test_caddy_empty_fallback_response_and_alt_svc() -> Result<()> {
    let _serial = test_lock().lock().await;
    let h3_port = 8443;
    let (addr, _metrics, server) = spawn_tls_caddy_server(Some(h3_port)).await?;

    let mut tls = tls_handshake(addr, &[b"http/1.1"]).await?;
    tls.write_all(
        b"GET /nonexistent-path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await?;

    let mut resp_bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut resp_bytes)).await??;
    let resp_str = String::from_utf8_lossy(&resp_bytes);

    assert!(resp_str.starts_with("HTTP/1.1 200 OK"), "expected 200 OK, got: {resp_str}");
    assert!(resp_str.contains("server: Caddy"), "expected server: Caddy header");
    assert!(
        resp_str.contains(&format!("alt-svc: h3=\":{h3_port}\"; ma=2592000")),
        "expected Alt-Svc header pointing to h3 port {h3_port}"
    );
    assert!(resp_str.contains("content-length: 0"), "expected content-length: 0");

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn test_h2_caddy_settings_and_response() -> Result<()> {
    let _serial = test_lock().lock().await;
    let h3_port = 9443;
    let (addr, _metrics, server) = spawn_tls_caddy_server(Some(h3_port)).await?;

    let tls = tls_handshake(addr, &[b"h2"]).await?;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()), "negotiated h2");

    let (mut send, conn) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .handshake(hyper_util::rt::TokioIo::new(tls))
            .await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = axum::http::Request::builder()
        .method("GET")
        .uri("https://localhost/unmapped")
        .header("host", "localhost")
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;
    let response = tokio::time::timeout(Duration::from_secs(2), send.send_request(req)).await??;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers().get("server").and_then(|v| v.to_str().ok()), Some("Caddy"));
    assert_eq!(
        response.headers().get("alt-svc").and_then(|v| v.to_str().ok()),
        Some(format!("h3=\":{h3_port}\"; ma=2592000").as_str())
    );
    assert_eq!(
        response.headers().get("content-length").and_then(|v| v.to_str().ok()),
        Some("0")
    );

    server.abort();
    let _ = server.await;
    Ok(())
}
