use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use axum::http::{Method, Request, StatusCode, Version, header};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper::ext::Protocol;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    WebSocketStream, connect_async,
    tungstenite::{Message as WsMessage, protocol},
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::super::{DnsCache, build_app, serve_tcp_listener};
use super::{build_test_state, config_ss_users, sample_config, write_test_h2_tls_cert};
use crate::crypto::{decrypt_udp_packet, encrypt_udp_packet};
use crate::metrics::Metrics;
use crate::protocol::TargetAddr;

#[tokio::test]
async fn websocket_rfc8441_http2_connect_smoke() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let config = sample_config(addr);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        &config,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth, None, None);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http::<Empty<Bytes>>();

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://{addr}/tcp"))
        .version(Version::HTTP_2)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .extension(Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())?;

    let mut response = client.request(req).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);

    let upgraded = hyper::upgrade::on(&mut response).await?;
    let upgraded = TokioIo::new(upgraded);
    let mut socket = WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;
    socket.close(None).await?;

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_http1_connect_still_works_with_root_auth_enabled() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let mut config = sample_config(addr);
    config.http_root_auth = true;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        &config,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth, None, None);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let (mut socket, _) = connect_async(format!("ws://{addr}/tcp")).await?;
    socket.close(None).await?;

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_http2_connect_still_works_with_root_auth_enabled() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let mut config = sample_config(addr);
    config.http_root_auth = true;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        &config,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth, None, None);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http::<Empty<Bytes>>();

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://{addr}/tcp"))
        .version(Version::HTTP_2)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .extension(Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())?;

    let mut response = client.request(req).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let upgraded = hyper::upgrade::on(&mut response).await?;
    let upgraded = TokioIo::new(upgraded);
    let mut socket = WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;
    socket.close(None).await?;

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_rfc8441_http2_udp_relay_smoke() -> Result<()> {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (read, peer) = upstream.recv_from(&mut buf).await?;
        upstream.send_to(&buf[..read], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let config = sample_config(addr);
    let user = config_ss_users(&config)[0].clone();
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        &config,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth, None, None);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http::<Empty<Bytes>>();

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://{addr}/udp"))
        .version(Version::HTTP_2)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .extension(Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())?;

    let mut response = client.request(req).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);

    let upgraded = hyper::upgrade::on(&mut response).await?;
    let upgraded = TokioIo::new(upgraded);
    let mut socket = WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;

    let mut plaintext = TargetAddr::from(upstream_addr).to_wire_bytes()?;
    plaintext.extend_from_slice(b"ping");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    socket.send(WsMessage::Binary(ciphertext.into())).await?;

    let reply = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next()).await?;
    let Some(Ok(WsMessage::Binary(encrypted_reply))) = reply else {
        anyhow::bail!("expected binary websocket reply, got {reply:?}");
    };

    let packet = decrypt_udp_packet(std::slice::from_ref(&user), &encrypted_reply)?;
    let (target, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
        .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
    assert_eq!(target, TargetAddr::from(upstream_addr));
    assert_eq!(&packet.payload[consumed..], b"ping");
    assert_eq!(upstream_task.await??, b"ping");

    socket.close(None).await?;
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_rfc8441_http2_tls_connect_smoke() -> Result<()> {
    super::super::ensure_rustls_provider_installed();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let config = sample_config(addr);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let metrics = Metrics::new(&config);
    let (routes, services, auth) = build_test_state(
        &config,
        Arc::clone(&metrics),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth, None, None);

    let (cert_path, key_path, cert_der) = write_test_h2_tls_cert()?;
    let mut tls_config = config.clone();
    tls_config.tls_cert_path = Some(cert_path.clone());
    tls_config.tls_key_path = Some(key_path.clone());
    let server = tokio::spawn(async move {
        serve_tcp_listener(
            listener,
            app,
            Arc::new(tls_config),
            None,
            metrics,
            ShutdownSignal::never(),
        )
        .await
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];

    let tcp = TcpStream::connect(addr).await?;
    let tls = TlsConnector::from(Arc::new(client_config))
        .connect(rustls::pki_types::ServerName::try_from("localhost".to_string())?, tcp)
        .await?;

    let (mut send_request, conn) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .handshake::<_, Empty<Bytes>>(TokioIo::new(tls))
        .await?;
    let driver = tokio::spawn(conn);

    let req = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost:{}/tcp", addr.port()))
        .version(Version::HTTP_2)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .extension(Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())?;

    let mut response = send_request.send_request(req).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);

    let upgraded = hyper::upgrade::on(&mut response).await?;
    let upgraded = TokioIo::new(upgraded);
    let mut socket = WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;
    socket.close(None).await?;

    driver.abort();
    server.abort();
    let _ = driver.await;
    let _ = server.await;
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);
    Ok(())
}

/// The client offers `Sec-WebSocket-Extensions` exactly as Chrome and Firefox
/// do but implements no extension, which is only sound because this server
/// never accepts one. That is a code invariant, not a build feature (cargo
/// feature unification enables `sockudo-ws`'s `permessage-deflate` in
/// workspace builds): the h3 response is built with
/// `build_extended_connect_response(_, None)`, the `sockudo-ws` `Config`
/// default is `Compression::Disabled`, and axum's upgrade response never
/// echoes the header. The client also refuses an accepted extension. Pin it
/// on h1 and h2 for both browsers' offers, and check frames still flow on the
/// upgraded socket.
#[tokio::test]
async fn websocket_upgrade_ignores_the_browser_permessage_deflate_offer() -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::handshake::client::generate_key;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let config = sample_config(addr);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        &config,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth, None, None);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    async fn ping_pong<S>(socket: &mut WebSocketStream<S>) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        socket.send(WsMessage::Ping(Bytes::from_static(b"p"))).await?;
        let reply = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("socket closed before the pong"))??;
        assert_eq!(reply, WsMessage::Pong(Bytes::from_static(b"p")));
        Ok(())
    }

    for offer in ["permessage-deflate; client_max_window_bits", "permessage-deflate"] {
        // HTTP/1.1 upgrade.
        let mut tcp = TcpStream::connect(addr).await?;
        let request = format!(
            "GET /tcp HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Extensions: {offer}\r\n\r\n",
            generate_key()
        );
        tcp.write_all(request.as_bytes()).await?;
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(tcp.read(&mut byte).await?, 1, "server closed during the upgrade");
            head.push(byte[0]);
        }
        let head = String::from_utf8(head)?.to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 101"), "{head}");
        assert!(!head.contains("sec-websocket-extensions"), "h1 accepted {offer}: {head}");
        let mut socket = WebSocketStream::from_raw_socket(tcp, protocol::Role::Client, None).await;
        ping_pong(&mut socket).await?;

        // HTTP/2 extended CONNECT.
        let client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http::<Empty<Bytes>>();
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("http://{addr}/tcp"))
            .version(Version::HTTP_2)
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_EXTENSIONS, offer)
            .extension(Protocol::from_static("websocket"))
            .body(Empty::<Bytes>::new())?;
        let mut response = client.request(req).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !response.headers().contains_key(header::SEC_WEBSOCKET_EXTENSIONS),
            "h2 accepted {offer}"
        );
        let upgraded = TokioIo::new(hyper::upgrade::on(&mut response).await?);
        let mut socket =
            WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;
        ping_pong(&mut socket).await?;
    }

    server.abort();
    let _ = server.await;
    Ok(())
}
