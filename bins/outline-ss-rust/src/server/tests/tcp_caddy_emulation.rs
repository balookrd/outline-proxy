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
    let app = build_app(routes, services, auth, None, None).route(
        "/large",
        axum::routing::get(|| async { axum::body::Bytes::from(vec![b'A'; 200 * 1024]) }),
    );
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

struct RecordingStream {
    inner: TcpStream,
    read_bytes: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncRead for RecordingStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let prev_len = buf.filled().len();
        let res = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &res {
            let newly_read = &buf.filled()[prev_len..];
            if !newly_read.is_empty() {
                self.read_bytes.lock().unwrap().extend_from_slice(newly_read);
            }
        }
        res
    }
}

impl tokio::io::AsyncWrite for RecordingStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default, Debug)]
struct TestSessionStore {
    inserted_tickets: std::sync::Mutex<Vec<String>>,
}

impl rustls::client::ClientSessionStore for TestSessionStore {
    fn set_kx_hint(&self, _server_name: ServerName<'static>, _group: rustls::NamedGroup) {}
    fn kx_hint(&self, _server_name: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        None
    }
    fn set_tls12_session(
        &self,
        _server_name: ServerName<'static>,
        _value: rustls::client::Tls12ClientSessionValue,
    ) {
    }
    fn tls12_session(
        &self,
        _server_name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        None
    }
    fn remove_tls12_session(&self, _server_name: &ServerName<'static>) {}
    fn insert_tls13_ticket(
        &self,
        _server_name: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.inserted_tickets.lock().unwrap().push(format!("{value:?}"));
    }
    fn take_tls13_ticket(
        &self,
        _server_name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        None
    }
}

fn parse_server_hello_extension_types(raw_bytes: &[u8]) -> Result<Vec<u16>> {
    let mut offset = 0;
    while offset + 5 <= raw_bytes.len() {
        let content_type = raw_bytes[offset];
        let record_len =
            u16::from_be_bytes([raw_bytes[offset + 3], raw_bytes[offset + 4]]) as usize;
        if offset + 5 + record_len > raw_bytes.len() {
            break;
        }
        let record_payload = &raw_bytes[offset + 5..offset + 5 + record_len];
        if content_type == 0x16 && !record_payload.is_empty() && record_payload[0] == 0x02 {
            let mut hs_offset = 4;
            hs_offset += 2 + 32;
            if hs_offset >= record_payload.len() {
                anyhow::bail!("malformed ServerHello: truncated before session_id");
            }
            let session_id_len = record_payload[hs_offset] as usize;
            hs_offset += 1 + session_id_len;
            hs_offset += 2 + 1;
            if hs_offset + 2 > record_payload.len() {
                anyhow::bail!("malformed ServerHello: truncated before extensions_len");
            }
            let ext_total_len =
                u16::from_be_bytes([record_payload[hs_offset], record_payload[hs_offset + 1]])
                    as usize;
            hs_offset += 2;
            let mut ext_types = Vec::new();
            let ext_end = hs_offset + ext_total_len;
            while hs_offset + 4 <= ext_end && ext_end <= record_payload.len() {
                let ext_type =
                    u16::from_be_bytes([record_payload[hs_offset], record_payload[hs_offset + 1]]);
                let ext_len = u16::from_be_bytes([
                    record_payload[hs_offset + 2],
                    record_payload[hs_offset + 3],
                ]) as usize;
                ext_types.push(ext_type);
                hs_offset += 4 + ext_len;
            }
            return Ok(ext_types);
        }
        offset += 5 + record_len;
    }
    anyhow::bail!("ServerHello not found in raw bytes");
}

fn parse_tls_record_lengths(raw_bytes: &[u8]) -> Vec<(u8, usize)> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset + 5 <= raw_bytes.len() {
        let content_type = raw_bytes[offset];
        let record_payload_len =
            u16::from_be_bytes([raw_bytes[offset + 3], raw_bytes[offset + 4]]) as usize;
        let total_len = 5 + record_payload_len;
        if offset + total_len > raw_bytes.len() {
            break;
        }
        records.push((content_type, total_len));
        offset += total_len;
    }
    records
}

#[tokio::test]
async fn test_tls13_caddy_server_hello_order_and_tickets() -> Result<()> {
    let _serial = test_lock().lock().await;
    let (addr, _metrics, server) = spawn_tls_caddy_server(None).await?;

    let inner_store = Arc::new(TestSessionStore::default());
    let session_store: Arc<dyn rustls::client::ClientSessionStore> = inner_store.clone();
    let mut client_config = permissive_client_config();
    client_config.resumption = rustls::client::Resumption::store(session_store);
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let raw_tcp = TcpStream::connect(addr).await?;
    let recorded_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recording_stream = RecordingStream {
        inner: raw_tcp,
        read_bytes: Arc::clone(&recorded_bytes),
    };

    let mut tls = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("localhost")?, recording_stream)
        .await?;

    // Verify ServerHello extensions order matches Caddy/Go:
    // 0x002b (supported_versions) -> 0x0033 (key_share)
    let raw = recorded_bytes.lock().unwrap().clone();
    let ext_types = parse_server_hello_extension_types(&raw)?;
    assert_eq!(
        ext_types,
        vec![0x002b, 0x0033],
        "ServerHello extensions must be ordered: [supported_versions, key_share], got: {ext_types:?}"
    );

    // Send HTTP request and read response so that post-handshake tickets are received
    tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut resp)).await??;

    // Small delay to ensure any post-handshake tickets are delivered
    for _ in 0..10 {
        if !inner_store.inserted_tickets.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Verify exactly 1 ticket was issued, with lifetime = 604800s (7 days, matching Go ticketLifetime)
    let tickets = inner_store.inserted_tickets.lock().unwrap().clone();
    assert_eq!(
        tickets.len(),
        1,
        "Caddy sends exactly 1 TLS 1.3 NewSessionTicket, got: {}",
        tickets.len()
    );
    assert!(
        tickets[0].contains("lifetime_secs: 604800"),
        "TLS 1.3 ticket lifetime must be 604800s (7 days), got: {}",
        tickets[0]
    );

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn test_tls_dynamic_record_sizing() -> Result<()> {
    let _serial = test_lock().lock().await;
    let (addr, _metrics, server) = spawn_tls_caddy_server(None).await?;

    let mut client_config = permissive_client_config();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let raw_tcp = TcpStream::connect(addr).await?;
    let recorded_bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recording_stream = RecordingStream {
        inner: raw_tcp,
        read_bytes: Arc::clone(&recorded_bytes),
    };

    let mut tls = TlsConnector::from(Arc::new(client_config))
        .connect(ServerName::try_from("localhost")?, recording_stream)
        .await?;

    // Request large 200 KiB response
    tls.write_all(b"GET /large HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut resp)).await??;
    assert!(resp.len() >= 200 * 1024, "received full response, got {} bytes", resp.len());

    let raw = recorded_bytes.lock().unwrap().clone();
    let records = parse_tls_record_lengths(&raw);
    let appdata_records: Vec<usize> = records
        .into_iter()
        .filter_map(|(typ, len)| if typ == 0x17 { Some(len) } else { None })
        .collect();

    assert!(!appdata_records.is_empty(), "expected appdata records");

    // Before crossing 128 KiB boost threshold: all early records must be <= 1208 bytes (tcpMSSEstimate)
    let early_records: Vec<usize> = appdata_records.iter().copied().take(100).collect();
    for (i, &len) in early_records.iter().enumerate() {
        assert!(len <= 1208, "early record #{i} exceeded TCP MSS limit 1208 bytes: {len}");
    }

    // After 128 KiB boost threshold: records should scale up (significantly larger than 1208)
    let has_boosted_records = appdata_records.iter().any(|&len| len > 1208);
    assert!(
        has_boosted_records,
        "records after 128 KiB boost threshold should grow larger than 1208 bytes"
    );

    server.abort();
    let _ = server.await;
    Ok(())
}
