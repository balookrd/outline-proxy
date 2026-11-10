//! The TLS listener bounds the wait for the first request after the
//! handshake. Without it a peer that completes TLS and then goes silent holds
//! a `TLS_MAX_CONCURRENT_CONNECTIONS` permit for good, and a prober sees a
//! connection no ordinary web server would keep open.

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

use super::super::bootstrap::{TestTlsFirstRequestTimeout, serve_tcp_listener};
use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::super::{DnsCache, build_app};
use super::build_test_state;
use super::sni_fallback::{make_sample_config_with_tls, permissive_client_config, test_lock};
use crate::metrics::Metrics;

/// Shrunk first-request budget, so a test waits a fraction of a second.
const BUDGET: Duration = Duration::from_millis(400);

async fn spawn_tls_server() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let (config, _cert_path, _key_path) = make_sample_config_with_tls(addr)?;
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
    let server = tokio::spawn(async move {
        serve_tcp_listener(listener, app, Arc::new(config), None, metrics, ShutdownSignal::never())
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    Ok((addr, server))
}

/// Completes a TLS handshake offering `alpn` and returns the stream with the
/// protocol the server picked.
async fn handshake(
    addr: SocketAddr,
    alpn: &[&[u8]],
) -> Result<(TlsStream<TcpStream>, Option<Vec<u8>>)> {
    let mut config = permissive_client_config();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let tcp = TcpStream::connect(addr).await?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost")?, tcp)
        .await?;
    let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    Ok((tls, negotiated))
}

/// Whether the server closes the connection within `within`. A close shows up
/// as EOF or, without a `close_notify`, as a read error; both count.
async fn closed_within(tls: &mut TlsStream<TcpStream>, within: Duration) -> bool {
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, tls.read(&mut buf)).await {
            Err(_) => return false,
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            // Server-initiated bytes (the h2 SETTINGS frame): keep reading.
            Ok(Ok(_)) => {},
        }
    }
}

#[tokio::test]
async fn a_silent_peer_is_dropped_after_the_handshake_whatever_its_alpn() -> Result<()> {
    let _serial = test_lock().lock().await;
    let _budget = TestTlsFirstRequestTimeout::set(BUDGET);
    let (addr, server) = spawn_tls_server().await?;

    let cases: [(&[&[u8]], Option<&[u8]>); 3] =
        [(&[b"h2"], Some(b"h2")), (&[b"http/1.1"], Some(b"http/1.1")), (&[], None)];
    for (offered, expected) in cases {
        let (mut tls, negotiated) = handshake(addr, offered).await?;
        assert_eq!(negotiated.as_deref(), expected, "unexpected ALPN for offer {offered:?}");
        assert!(
            closed_within(&mut tls, BUDGET * 8).await,
            "silent peer with ALPN {expected:?} was not dropped after the handshake",
        );
    }

    server.abort();
    Ok(())
}

/// A partial HTTP/2 preface must not buy more time than no preface at all.
#[tokio::test]
async fn a_partial_h2_preface_is_dropped_too() -> Result<()> {
    let _serial = test_lock().lock().await;
    let _budget = TestTlsFirstRequestTimeout::set(BUDGET);
    let (addr, server) = spawn_tls_server().await?;

    let (mut tls, _) = handshake(addr, &[b"h2"]).await?;
    tls.write_all(b"PRI * HTTP/2.0").await?;
    tls.flush().await?;
    assert!(closed_within(&mut tls, BUDGET * 8).await, "partial preface kept the connection");

    server.abort();
    Ok(())
}

/// The deadline bounds the *first* request only: an HTTP/2 connection that
/// sent its preface stays open while idle, as the client's connection pool
/// relies on.
#[tokio::test]
async fn an_h2_connection_that_sent_its_preface_outlives_the_budget() -> Result<()> {
    let _serial = test_lock().lock().await;
    let _budget = TestTlsFirstRequestTimeout::set(BUDGET);
    let (addr, server) = spawn_tls_server().await?;

    let (mut tls, _) = handshake(addr, &[b"h2"]).await?;
    // Client preface followed by an empty SETTINGS frame.
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        .await?;
    tls.flush().await?;
    assert!(
        !closed_within(&mut tls, BUDGET * 4).await,
        "an established idle h2 connection was closed by the first-request deadline",
    );

    server.abort();
    Ok(())
}

/// A request that arrives inside the budget is served as before.
#[tokio::test]
async fn a_request_within_the_budget_is_served() -> Result<()> {
    let _serial = test_lock().lock().await;
    let _budget = TestTlsFirstRequestTimeout::set(BUDGET);
    let (addr, server) = spawn_tls_server().await?;

    for offered in [&[b"http/1.1".as_slice()][..], &[][..]] {
        let (mut tls, _) = handshake(addr, offered).await?;
        tokio::time::sleep(BUDGET / 4).await;
        tls.write_all(b"GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut response)).await;
        let head = String::from_utf8_lossy(&response);
        assert!(head.starts_with("HTTP/1.1 404"), "offer {offered:?}: got {head:?}");
    }

    server.abort();
    Ok(())
}
