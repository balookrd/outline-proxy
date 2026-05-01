//! End-to-end coverage for the L4 `[sni_fallback]` dispatcher.
//!
//! Each test stands up a real TLS listener wired with the production
//! `serve_tcp_listener`, points it at a raw-TCP fake backend, then
//! drives a `tokio_rustls::TlsConnector` from the test side with a
//! chosen SNI to assert which side handled the connection.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use rustls::{
    ClientConfig, RootCertStore,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex as AsyncMutex, oneshot},
};
use tokio_rustls::TlsConnector;

/// Cargo runs `#[tokio::test]`s on multiple OS threads with one tokio
/// runtime each. With several listeners + TLS handshakes contending
/// for the same process-wide rustls crypto provider and the same OS
/// ephemeral port pool, parallel runs surface as `Connection refused`
/// flakes. Serialise the suite — three tests, ~3 s total, not worth a
/// `serial_test` dep just for this.
fn test_lock() -> &'static AsyncMutex<()> {
    static LOCK: std::sync::OnceLock<AsyncMutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

use super::super::bootstrap::serve_tcp_listener;
use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::super::transport::sni_fallback::SniFallbackContext;
use super::super::{DnsCache, build_app, build_user_routes};
use super::{build_test_state, sample_config};
use crate::config::{Config, ProxyProtocolVersion, SniBackend, SniFallbackConfig, SniMatcher};
use crate::metrics::Metrics;

/// Spawns a raw-TCP backend that captures everything the splice path
/// writes to it. The backend keeps the socket open so `copy_bidirectional`
/// does not race a half-close before we collect enough bytes.
async fn spawn_capture_backend() -> Result<(SocketAddr, oneshot::Receiver<Vec<u8>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel::<Vec<u8>>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            // Pull bytes off the splice until either we have enough
            // to assert on (~512 B covers PROXY v2 + TLS ClientHello)
            // or the inbound side stops talking for ~250 ms.
            loop {
                let read = tokio::time::timeout(
                    Duration::from_millis(250),
                    stream.read(&mut buf[total..]),
                )
                .await;
                match read {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        total += n;
                        if total >= 512 {
                            break;
                        }
                    },
                }
            }
            buf.truncate(total);
            if let Some(tx) = tx.lock().await.take() {
                let _ = tx.send(buf);
            }
            // Hold the inbound half open briefly so the splice's
            // copy_bidirectional doesn't drop its end mid-write.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = stream.shutdown().await;
        }
    });
    Ok((addr, rx))
}

/// Trust-everything verifier so the test client doesn't need to know
/// the server cert: tests assert on which side handled the connection,
/// not on cert chain validity.
#[derive(Debug)]
struct AcceptAnyServer;

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn permissive_client_config() -> ClientConfig {
    super::super::ensure_rustls_provider_installed();
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_no_client_auth()
}

fn write_temp_pem(prefix: &str, contents: &str) -> Result<std::path::PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "outline-ss-rust-sni-fallback-{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::write(&path, contents)?;
    Ok(path)
}

fn make_sample_config_with_tls(listen: SocketAddr) -> Result<(Config, std::path::PathBuf, std::path::PathBuf)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();
    let cert_path = write_temp_pem("cert", &cert_pem)?;
    let key_path = write_temp_pem("key", &key_pem)?;
    let mut config = sample_config(listen);
    config.tls_cert_path = Some(cert_path.clone());
    config.tls_key_path = Some(key_path.clone());
    Ok((config, cert_path, key_path))
}

fn sni_ctx(
    backend: SocketAddr,
    inbound_listen: SocketAddr,
    proxy_protocol: Option<ProxyProtocolVersion>,
    allow_no_sni: bool,
) -> Arc<SniFallbackContext> {
    Arc::new(SniFallbackContext {
        config: Arc::new(SniFallbackConfig {
            match_sni: vec![SniMatcher::Exact("localhost".into())],
            allow_no_sni,
            max_client_hello_bytes: 8192,
            backends: vec![SniBackend {
                authority: backend.to_string(),
                match_sni: vec![],
                proxy_protocol,
            }],
        }),
        inbound_listen,
    })
}

#[tokio::test]
async fn matched_sni_terminates_locally() -> Result<()> {
    let _serial = test_lock().lock().await;
    let (backend_addr, backend_rx) = spawn_capture_backend().await?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (config, _cert_path, _key_path) = make_sample_config_with_tls(addr)?;
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));
    let metrics = Metrics::new(&config);
    let (routes, services_state, auth) = build_test_state(
        user_routes,
        Arc::clone(&metrics),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services_state, auth, None);
    let sni_fallback = Some(sni_ctx(backend_addr, addr, None, false));
    let server_config = Arc::new(config);
    let shutdown = ShutdownSignal::never();
    let server = tokio::spawn(async move {
        serve_tcp_listener(listener, app, server_config, sni_fallback, metrics, shutdown).await
    });
    // Give the server task one scheduler tick to reach `listener.accept()`
    // — without this, parallel-test scheduling sometimes lets the client
    // connect race the spawn and the OS fires a RST.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Client dials with SNI = "localhost" — must hit our local TLS
    // terminator, get back a valid TLS handshake and then a 404 from
    // axum's fallback.
    let connector = TlsConnector::from(Arc::new(permissive_client_config()));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost")?;
    let mut tls = connector.connect(server_name, tcp).await?;
    tls.write_all(
        b"GET /not-a-real-path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut response))
        .await
        .context("client read timed out")??;
    let head = std::str::from_utf8(&response).unwrap_or("");
    assert!(
        head.starts_with("HTTP/1.1 404"),
        "expected our 404, got: {head:?}"
    );
    // Backend MUST NOT have seen anything.
    let backend_seen =
        tokio::time::timeout(Duration::from_millis(200), backend_rx).await;
    assert!(backend_seen.is_err(), "backend was unexpectedly hit");

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn foreign_sni_splices_to_backend_with_clienthello() -> Result<()> {
    let _serial = test_lock().lock().await;
    let (backend_addr, backend_rx) = spawn_capture_backend().await?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (config, _cert_path, _key_path) = make_sample_config_with_tls(addr)?;
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));
    let metrics = Metrics::new(&config);
    let (routes, services_state, auth) = build_test_state(
        user_routes,
        Arc::clone(&metrics),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services_state, auth, None);
    let sni_fallback = Some(sni_ctx(backend_addr, addr, None, false));
    let server_config = Arc::new(config);
    let shutdown = ShutdownSignal::never();
    let server = tokio::spawn(async move {
        serve_tcp_listener(listener, app, server_config, sni_fallback, metrics, shutdown).await
    });
    // Give the server task one scheduler tick to reach `listener.accept()`
    // — without this, parallel-test scheduling sometimes lets the client
    // connect race the spawn and the OS fires a RST.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Client dials with SNI = "foreign.example" — the dispatcher must
    // splice the raw TCP (including the captured ClientHello) to the
    // backend. The TLS handshake will eventually fail because the
    // backend doesn't speak TLS, but the test only cares that the
    // backend received the ClientHello bytes.
    let connector = TlsConnector::from(Arc::new(permissive_client_config()));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("foreign.example")?;
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        connector.connect(server_name, tcp),
    )
    .await;

    let captured = tokio::time::timeout(Duration::from_secs(1), backend_rx)
        .await
        .context("backend never received the splice")??;
    assert!(!captured.is_empty(), "backend got an empty splice");
    // First TLS record byte = 0x16 (handshake), version major = 0x03.
    assert_eq!(captured[0], 0x16, "splice did not start with a TLS record");
    assert_eq!(captured[1], 0x03, "splice TLS record has wrong version major");
    // Look for the SNI string in the captured ClientHello — it MUST
    // be present, otherwise we forwarded the wrong stream.
    let needle = b"foreign.example";
    assert!(
        captured.windows(needle.len()).any(|w| w == needle),
        "ClientHello forwarded to backend missing SNI 'foreign.example'"
    );

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn foreign_sni_with_proxy_protocol_v2_prefixes_header() -> Result<()> {
    let _serial = test_lock().lock().await;
    let (backend_addr, backend_rx) = spawn_capture_backend().await?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (config, _cert_path, _key_path) = make_sample_config_with_tls(addr)?;
    let user_routes = build_user_routes(&config)?;
    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));
    let metrics = Metrics::new(&config);
    let (routes, services_state, auth) = build_test_state(
        user_routes,
        Arc::clone(&metrics),
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services_state, auth, None);
    let sni_fallback = Some(sni_ctx(
        backend_addr,
        addr,
        Some(ProxyProtocolVersion::V2),
        false,
    ));
    let server_config = Arc::new(config);
    let shutdown = ShutdownSignal::never();
    let server = tokio::spawn(async move {
        serve_tcp_listener(listener, app, server_config, sni_fallback, metrics, shutdown).await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let connector = TlsConnector::from(Arc::new(permissive_client_config()));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("foreign.example")?;
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        connector.connect(server_name, tcp),
    )
    .await;

    let captured = tokio::time::timeout(Duration::from_secs(1), backend_rx)
        .await
        .context("backend never received the splice")??;
    assert!(captured.len() >= 28, "PROXY v2 header truncated");
    assert_eq!(
        &captured[..12],
        &[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]
    );
    assert_eq!(captured[12], 0x21, "expected ver=2 cmd=PROXY");
    assert_eq!(captured[13], 0x11, "expected AF_INET + STREAM");
    let after_header = &captured[28..];
    assert!(
        after_header.starts_with(&[0x16, 0x03]),
        "PROXY v2 header was not followed by a TLS ClientHello: {:?}",
        &after_header[..after_header.len().min(8)]
    );
    let needle = b"foreign.example";
    assert!(
        after_header.windows(needle.len()).any(|w| w == needle),
        "ClientHello forwarded to backend missing SNI 'foreign.example'"
    );

    server.abort();
    let _ = server.await;
    Ok(())
}

