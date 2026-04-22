use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result};
use axum::http::{Method, Request, StatusCode, Version, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use h3::ext::Protocol as H3Protocol;
use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper::ext::Protocol;
use hyper_util::{
    client::legacy::Client,
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, Message as H3Message, Role as H3Role,
    Stream as H3Stream, WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    WebSocketStream, connect_async,
    tungstenite::{Message as WsMessage, protocol},
};

use super::bootstrap::serve_listener;
use super::connect::{connect_tcp_addrs, connect_tcp_target, sort_addrs_for_happy_eyeballs};
use super::shutdown::ShutdownSignal;
use super::{
    AuthPolicy, DnsCache, RouteRegistry, Services, build_app, build_transport_route_map,
    build_users, serve_h3_server, serve_ss_tcp_listener, serve_ss_udp_socket, serve_tcp_listener,
};
use crate::config::{CipherKind, Config, UserEntry};
use crate::crypto::{
    AeadStreamDecryptor, AeadStreamEncryptor, UserKey, decrypt_udp_packet, encrypt_udp_packet,
};
use crate::metrics::{Metrics, Transport};
use super::nat::NatTable;
use crate::protocol::TargetAddr;

fn build_test_state(
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    http_root_auth: bool,
    http_root_realm: impl Into<Arc<str>>,
) -> (Arc<RouteRegistry>, Arc<Services>, Arc<AuthPolicy>) {
    let tcp = Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp));
    let udp = Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp));
    let routes = Arc::new(RouteRegistry { tcp, udp });
    let services = Arc::new(Services {
        metrics,
        nat_table,
        dns_cache,
        prefer_ipv4_upstream: false,
        outbound_ipv6: None,
        udp_relay_semaphore: None,
    });
    let auth = Arc::new(AuthPolicy {
        users,
        http_root_auth,
        http_root_realm: http_root_realm.into(),
    });
    (routes, services, auth)
}

#[tokio::test]
async fn tcp_ipv6_loopback_smoke() -> Result<()> {
    let listener = match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(listener) => listener,
        Err(error) if ipv6_unavailable(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(buf)
    });

    let target = TargetAddr::Socket(SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let mut client = connect_tcp_target(dns_cache.as_ref(), &target, None, false, None).await?;
    client.write_all(b"ping").await?;

    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).await?;

    assert_eq!(&reply, b"pong");
    assert_eq!(server.await??, *b"ping");
    Ok(())
}

#[test]
fn tcp_connect_order_interleaves_ipv4_and_ipv6() {
    let ordered = sort_addrs_for_happy_eyeballs(
        vec![
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
        ],
        false,
    );

    assert_eq!(
        ordered,
        vec![
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
            SocketAddr::from(([2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443)),
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 443)),
        ]
    );
}

#[test]
fn dns_cache_returns_fresh_entries_and_expires() {
    let cache = DnsCache::new(std::time::Duration::from_millis(5));
    let resolved = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));
    let entry: Arc<[SocketAddr]> = Arc::from(vec![resolved].into_boxed_slice());

    cache.store("dns.google", 53, false, entry);
    assert_eq!(cache.lookup_one("dns.google", 53, false), Some(resolved));

    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_eq!(cache.lookup_one("dns.google", 53, false), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_cache_singleflight_coalesces_concurrent_misses() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cache = DnsCache::new(std::time::Duration::from_secs(30));
    let invocations = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(tokio::sync::Barrier::new(16));

    let resolved: Arc<[SocketAddr]> =
        Arc::from(vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 443))].into_boxed_slice());

    let mut handles = Vec::new();
    for _ in 0..16 {
        let cache = Arc::clone(&cache);
        let invocations = Arc::clone(&invocations);
        let barrier = Arc::clone(&barrier);
        let resolved = Arc::clone(&resolved);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            cache
                .resolve_or_join("slow.example", 443, false, |cache| {
                    let invocations = Arc::clone(&invocations);
                    let resolved = Arc::clone(&resolved);
                    async move {
                        invocations.fetch_add(1, Ordering::SeqCst);
                        // Give other waiters a chance to enter the singleflight slot.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        cache.store("slow.example", 443, false, Arc::clone(&resolved));
                        Ok(resolved)
                    }
                })
                .await
                .expect("resolve succeeds")
        }));
    }

    for handle in handles {
        let addrs = handle.await.expect("task joins");
        assert_eq!(addrs.as_ref(), resolved.as_ref());
    }

    assert_eq!(invocations.load(Ordering::SeqCst), 1, "loader must run once");
}

#[tokio::test]
async fn dns_cache_singleflight_propagates_errors() {
    let cache = DnsCache::new(std::time::Duration::from_secs(30));
    let err = cache
        .resolve_or_join("fail.example", 443, false, |_| async move {
            Err(anyhow::anyhow!("boom"))
        })
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("boom"));

    // After failure the slot is released: a fresh call runs the loader again.
    let resolved: Arc<[SocketAddr]> =
        Arc::from(vec![SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 1))].into_boxed_slice());
    let resolved2 = Arc::clone(&resolved);
    let ok = cache
        .resolve_or_join("fail.example", 443, false, move |_| {
            let resolved2 = Arc::clone(&resolved2);
            async move { Ok(resolved2) }
        })
        .await
        .expect("second call succeeds");
    assert_eq!(ok.as_ref(), resolved.as_ref());
}

#[tokio::test]
async fn tcp_connect_tries_next_resolved_address() -> Result<()> {
    let blocked_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let blocked_addr = blocked_listener.local_addr()?;
    drop(blocked_listener);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(buf)
    });

    let mut client = connect_tcp_addrs(&[blocked_addr, addr], None, None).await?;
    client.write_all(b"ping").await?;

    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).await?;

    assert_eq!(&reply, b"pong");
    assert_eq!(server.await??, *b"ping");
    Ok(())
}

#[tokio::test]
async fn udp_ipv6_loopback_smoke() -> Result<()> {
    let echo = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(s) => s,
        Err(error) if ipv6_unavailable(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let echo_addr = echo.local_addr()?;
    let server = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (read, peer) = echo.recv_from(&mut buf).await?;
        echo.send_to(&buf[..read], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
    });

    // Send a datagram to the echo server and wait for the reply.
    let client = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
    client.send_to(b"ping", echo_addr).await?;
    let mut buf = [0_u8; 64];
    let (read, source) =
        tokio::time::timeout(std::time::Duration::from_secs(2), client.recv_from(&mut buf))
            .await??;

    assert_eq!(source.ip(), Ipv6Addr::LOCALHOST);
    assert_eq!(&buf[..read], b"ping");
    assert_eq!(server.await??, b"ping");
    Ok(())
}

#[tokio::test]
async fn websocket_rfc8441_http2_connect_smoke() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let config = sample_config(addr);
    let users = build_users(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth);
    let server = tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

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
    let users = build_users(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth);
    let server = tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

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
    let users = build_users(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth);
    let server = tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

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
    let users = build_users(&config)?;
    let user = users[0].clone();
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth);
    let server = tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

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

    let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
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
    assert_eq!(target, TargetAddr::Socket(upstream_addr));
    assert_eq!(&packet.payload[consumed..], b"ping");
    assert_eq!(upstream_task.await??, b"ping");

    socket.close(None).await?;
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_rfc8441_http2_tls_connect_smoke() -> Result<()> {
    super::ensure_rustls_provider_installed();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let config = sample_config(addr);
    let users = build_users(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth);

    let (cert_path, key_path, cert_der) = write_test_h2_tls_cert()?;
    let mut tls_config = config.clone();
    tls_config.tls_cert_path = Some(cert_path.clone());
    tls_config.tls_key_path = Some(key_path.clone());
    let server =
        tokio::spawn(async move {
            serve_tcp_listener(listener, app, Arc::new(tls_config), ShutdownSignal::never()).await
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

#[tokio::test]
async fn websocket_tcp_path_isolates_users_by_route() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config_with_users(
        listen_addr,
        vec![
            UserEntry {
                id: "alice".into(),
                password: "secret-a".into(),
                fwmark: None,
                method: None,
                ws_path_tcp: Some("/alice-tcp".into()),
                ws_path_udp: Some("/alice-udp".into()),
            },
            UserEntry {
                id: "bob".into(),
                password: "secret-b".into(),
                fwmark: None,
                method: None,
                ws_path_tcp: Some("/bob-tcp".into()),
                ws_path_udp: Some("/bob-udp".into()),
            },
        ],
    );
    let users = build_users(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth);
    let server = tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let bob = users
        .iter()
        .find(|user| user.id() == "bob")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing bob user"))?;
    let (mut socket, _) = connect_async(format!("ws://{listen_addr}/alice-tcp")).await?;
    let mut request = TargetAddr::Socket(upstream_addr).encode()?;
    request.extend_from_slice(b"ping");
    let mut encryptor = AeadStreamEncryptor::new(&bob, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&request, &mut buf)?;
    socket.send(WsMessage::Binary(buf.freeze())).await?;

    let client_outcome =
        tokio::time::timeout(std::time::Duration::from_secs(1), socket.next()).await;
    assert!(
        matches!(client_outcome, Ok(Some(Ok(WsMessage::Close(_)))) | Ok(Some(Err(_))) | Ok(None)),
        "unexpected websocket outcome: {client_outcome:?}"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), upstream.accept())
            .await
            .is_err(),
        "bob key on alice path must not reach upstream"
    );

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn root_http_auth_challenges_allows_password_and_hides_other_paths() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let mut config = sample_config(addr);
    config.http_root_auth = true;
    config.http_root_realm = "My VPN \"Portal\"".into();
    let users = build_users(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth);
    let server = tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE),
        Some(&header::HeaderValue::from_static("Basic realm=\"My VPN \\\"Portal\\\"\""))
    );
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .context("missing auth challenge cookie")?
            .to_str()?
            .contains("Max-Age=300")
    );
    let challenge_cookie = set_cookie_pair(&response)?;
    assert_eq!(challenge_cookie, "outline_ss_root_auth=0");

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/"))
                .header(header::COOKIE, challenge_cookie.as_str())
                .header(header::AUTHORIZATION, basic_auth_header("secret-b"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .context("missing auth reset cookie")?
            .to_str()?
            .contains("Max-Age=0")
    );

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/tcp"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = client
        .request(
            Request::builder()
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

#[tokio::test]
async fn root_http_auth_returns_403_after_three_failed_password_attempts() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;

    let mut config = sample_config(addr);
    config.http_root_auth = true;
    let users = build_users(&config)?;
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let app = build_app(routes, services, auth);
    let server = tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let client = Client::builder(TokioExecutor::new()).build_http::<Empty<Bytes>>();

    let response = client
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("http://{addr}/"))
                .body(Empty::<Bytes>::new())?,
        )
        .await?;
    let mut cookie = set_cookie_pair(&response)?;

    for attempt in 1..=3 {
        let response = client
            .request(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("http://{addr}/"))
                    .header(header::COOKIE, cookie.as_str())
                    .header(header::AUTHORIZATION, basic_auth_header("wrong-password"))
                    .body(Empty::<Bytes>::new())?,
            )
            .await?;

        let expected_status = if attempt < 3 {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(response.status(), expected_status);
        assert!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .context("missing auth attempt cookie")?
                .to_str()?
                .contains("Max-Age=300")
        );
        cookie = set_cookie_pair(&response)?;
        assert_eq!(cookie, format!("outline_ss_root_auth={attempt}"));
    }

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn plain_shadowsocks_tcp_relay_smoke() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut buf = [0_u8; 16];
        stream.read_exact(&mut buf[..4]).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(buf[..4].to_vec())
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
    let users = build_users(&config)?;
    let user = users[0].clone();
    let metrics = Metrics::new(&config);
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let server = tokio::spawn(async move {
        serve_ss_tcp_listener(
            listener,
            users,
            metrics,
            dns_cache,
            false,
            None,
            ShutdownSignal::never(),
        )
        .await
    });

    let mut client = TcpStream::connect(listen_addr).await?;
    let mut request = TargetAddr::Socket(upstream_addr).encode()?;
    request.extend_from_slice(b"ping");
    let mut encryptor = AeadStreamEncryptor::new(&user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&request, &mut buf)?;
    client.write_all(&buf).await?;

    let mut encrypted_reply = [0_u8; 256];
    let read =
        tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut encrypted_reply))
            .await??;
    assert!(read > 0);

    let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user].into_boxed_slice()));
    let mut plaintext = Vec::new();
    decryptor.feed_ciphertext(&encrypted_reply[..read]);
    decryptor.drain_plaintext(&mut plaintext)?;
    assert_eq!(plaintext, b"pong");
    assert_eq!(upstream_task.await??, b"ping");

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_rfc9220_http3_connect_smoke() -> Result<()> {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let server =
        H3WebSocketServer::<H3Transport>::bind(server_addr, tls_config, H3WsConfig::default())
            .await?;
    let addr = server.local_addr()?;

    let config = sample_config(addr);
    let users = build_users(&config)?;
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users,
        metrics,
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let server = tokio::spawn(async move {
        serve_h3_server(server, routes, services, auth, ShutdownSignal::never()).await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(test_h3_client_config(cert_der)?);

    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost:{}/tcp", addr.port()))
        .version(Version::HTTP_3)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .extension(H3Protocol::WEBSOCKET)
        .body(())?;

    let stream = send_request.send_request(request).await?;
    let mut stream = stream;
    let response = stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_3);

    let h3_stream = H3Stream::<H3Transport>::from_h3_client(stream);
    let mut socket = H3WebSocketStream::from_raw(h3_stream, H3Role::Client, H3WsConfig::default());
    socket.send(H3Message::Close(None)).await?;

    driver.abort();
    server.abort();
    let _ = driver.await;
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn http3_root_auth_challenges_get_root_when_enabled() -> Result<()> {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let server =
        H3WebSocketServer::<H3Transport>::bind(server_addr, tls_config, H3WsConfig::default())
            .await?;
    let addr = server.local_addr()?;

    let mut config = sample_config(addr);
    config.h3_listen = Some(addr);
    config.h3_cert_path = Some("cert.pem".into());
    config.h3_key_path = Some("key.pem".into());
    config.http_root_auth = true;
    let users = build_users(&config)?;
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users,
        metrics,
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let server = tokio::spawn(async move {
        serve_h3_server(server, routes, services, auth, ShutdownSignal::never()).await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(test_h3_client_config(cert_der)?);

    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("https://localhost:{}/", addr.port()))
        .version(Version::HTTP_3)
        .body(())?;

    let mut stream = send_request.send_request(request).await?;
    let response = stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .context("missing HTTP/3 auth challenge cookie")?
            .to_str()?
            .contains("Max-Age=300")
    );

    driver.abort();
    server.abort();
    let _ = driver.await;
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_http3_connect_still_works_with_root_auth_enabled() -> Result<()> {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let server =
        H3WebSocketServer::<H3Transport>::bind(server_addr, tls_config, H3WsConfig::default())
            .await?;
    let addr = server.local_addr()?;

    let mut config = sample_config(addr);
    config.h3_listen = Some(addr);
    config.h3_cert_path = Some("cert.pem".into());
    config.h3_key_path = Some("key.pem".into());
    config.http_root_auth = true;
    let users = build_users(&config)?;
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users,
        metrics,
        nat_table,
        dns_cache,
        true,
        config.http_root_realm.clone(),
    );
    let server = tokio::spawn(async move {
        serve_h3_server(server, routes, services, auth, ShutdownSignal::never()).await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(test_h3_client_config(cert_der)?);

    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost:{}/tcp", addr.port()))
        .version(Version::HTTP_3)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .extension(H3Protocol::WEBSOCKET)
        .body(())?;

    let mut stream = send_request.send_request(request).await?;
    let response = stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK);

    let h3_stream = H3Stream::<H3Transport>::from_h3_client(stream);
    let mut socket = H3WebSocketStream::from_raw(h3_stream, H3Role::Client, H3WsConfig::default());
    socket.send(H3Message::Close(None)).await?;

    driver.abort();
    server.abort();
    let _ = driver.await;
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn plain_shadowsocks_udp_relay_smoke() -> Result<()> {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        let (read, peer) = upstream.recv_from(&mut buf).await?;
        upstream.send_to(&buf[..read], peer).await?;
        Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
    });

    let listener = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    let listen_addr = listener.local_addr()?;
    let config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000)));
    let users = build_users(&config)?;
    let user = users[0].clone();
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let server = tokio::spawn(async move {
        serve_ss_udp_socket(
            listener,
            users,
            metrics,
            nat_table,
            dns_cache,
            false,
            ShutdownSignal::never(),
        )
        .await
    });

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
    plaintext.extend_from_slice(b"ping");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    client.send_to(&ciphertext, listen_addr).await?;

    let mut encrypted_reply = [0_u8; 256];
    let (read, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut encrypted_reply),
    )
    .await??;

    let packet = decrypt_udp_packet(std::slice::from_ref(&user), &encrypted_reply[..read])?;
    let (target, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
        .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
    assert_eq!(target, TargetAddr::Socket(upstream_addr));
    assert_eq!(&packet.payload[consumed..], b"ping");
    assert_eq!(upstream_task.await??, b"ping");

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn plain_shadowsocks_udp_reuses_nat_entry_after_client_reconnect() -> Result<()> {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut peers = Vec::new();
        let mut buf = [0_u8; 64];
        for expected in [b"ping-1".as_slice(), b"ping-2".as_slice()] {
            let (read, peer) = upstream.recv_from(&mut buf).await?;
            peers.push(peer);
            assert_eq!(&buf[..read], expected);
            let reply = if expected == b"ping-1" {
                b"pong-1".as_slice()
            } else {
                b"pong-2".as_slice()
            };
            upstream.send_to(reply, peer).await?;
        }
        Result::<_, anyhow::Error>::Ok(peers)
    });

    let listener = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    let listen_addr = listener.local_addr()?;
    let config = sample_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 3000)));
    let users = build_users(&config)?;
    let user = users[0].clone();
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let server = tokio::spawn(async move {
        serve_ss_udp_socket(
            listener,
            users,
            metrics,
            nat_table,
            dns_cache,
            false,
            ShutdownSignal::never(),
        )
        .await
    });

    let client1 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    send_encrypted_udp_request(&client1, listen_addr, upstream_addr, b"ping-1", &user).await?;
    let response1 = recv_decrypted_udp_response(&client1, &user).await?;
    assert_eq!(response1, b"pong-1");
    drop(client1);

    let client2 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    send_encrypted_udp_request(&client2, listen_addr, upstream_addr, b"ping-2", &user).await?;
    let response2 = recv_decrypted_udp_response(&client2, &user).await?;
    assert_eq!(response2, b"pong-2");

    let peers = upstream_task.await??;
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0], peers[1], "NAT socket source port should stay stable across reconnect");

    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_rfc8441_http2_udp_reuses_nat_entry_after_client_reconnect() -> Result<()> {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut peers = Vec::new();
        let mut buf = [0_u8; 64];
        for expected in [b"ping-1".as_slice(), b"ping-2".as_slice()] {
            let (read, peer) = upstream.recv_from(&mut buf).await?;
            peers.push(peer);
            assert_eq!(&buf[..read], expected);
            let reply = if expected == b"ping-1" { b"pong-1".as_slice() } else { b"pong-2".as_slice() };
            upstream.send_to(reply, peer).await?;
        }
        Result::<_, anyhow::Error>::Ok(peers)
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let config = sample_config(addr);
    let users = build_users(&config)?;
    let user = users[0].clone();
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users.clone(),
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth);
    let server = tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let (mut send_request, conn) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .handshake::<_, Empty<Bytes>>(TokioIo::new(tcp))
        .await?;
    let driver = tokio::spawn(conn);

    for (payload, expected_reply) in [
        (b"ping-1".as_slice(), b"pong-1".as_slice()),
        (b"ping-2".as_slice(), b"pong-2".as_slice()),
    ] {
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("http://{addr}/udp"))
            .version(Version::HTTP_2)
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .extension(Protocol::from_static("websocket"))
            .body(Empty::<Bytes>::new())?;
        let mut response = send_request.send_request(req).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let upgraded = hyper::upgrade::on(&mut response).await?;
        let mut socket = WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded),
            protocol::Role::Client,
            None,
        )
        .await;

        let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
        plaintext.extend_from_slice(payload);
        socket.send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into())).await?;

        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next()).await?;
        let Some(Ok(WsMessage::Binary(enc_reply))) = reply else {
            anyhow::bail!("expected binary ws reply for {payload:?}, got {reply:?}");
        };
        let pkt = decrypt_udp_packet(std::slice::from_ref(&user), &enc_reply)?;
        let (_, consumed) = crate::protocol::parse_target_addr(&pkt.payload)?
            .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
        assert_eq!(&pkt.payload[consumed..], expected_reply);
        socket.close(None).await?;
    }

    let peers = upstream_task.await??;
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0], peers[1], "NAT socket source port should stay stable across WS reconnect");

    driver.abort();
    server.abort();
    let _ = driver.await;
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_rfc9220_http3_udp_reuses_nat_entry_after_client_reconnect() -> Result<()> {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut peers = Vec::new();
        let mut buf = [0_u8; 64];
        for expected in [b"ping-1".as_slice(), b"ping-2".as_slice()] {
            let (read, peer) = upstream.recv_from(&mut buf).await?;
            peers.push(peer);
            assert_eq!(&buf[..read], expected);
            let reply = if expected == b"ping-1" { b"pong-1".as_slice() } else { b"pong-2".as_slice() };
            upstream.send_to(reply, peer).await?;
        }
        Result::<_, anyhow::Error>::Ok(peers)
    });

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let server =
        H3WebSocketServer::<H3Transport>::bind(server_addr, tls_config, H3WsConfig::default())
            .await?;
    let addr = server.local_addr()?;

    let config = sample_config(addr);
    let users = build_users(&config)?;
    let user = users[0].clone();
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        users,
        metrics,
        nat_table,
        dns_cache,
        false,
        config.http_root_realm.clone(),
    );
    let server = tokio::spawn(async move {
        serve_h3_server(server, routes, services, auth, ShutdownSignal::never()).await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(test_h3_client_config(cert_der)?);

    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    for (payload, expected_reply) in [
        (b"ping-1".as_slice(), b"pong-1".as_slice()),
        (b"ping-2".as_slice(), b"pong-2".as_slice()),
    ] {
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://localhost:{}/udp", addr.port()))
            .version(Version::HTTP_3)
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .extension(H3Protocol::WEBSOCKET)
            .body(())?;
        let mut stream = send_request.send_request(request).await?;
        let response = stream.recv_response().await?;
        assert_eq!(response.status(), StatusCode::OK);

        let h3_stream = H3Stream::<H3Transport>::from_h3_client(stream);
        let mut socket =
            H3WebSocketStream::from_raw(h3_stream, H3Role::Client, H3WsConfig::default());

        let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
        plaintext.extend_from_slice(payload);
        socket
            .send(H3Message::Binary(Bytes::from(encrypt_udp_packet(&user, &plaintext)?)))
            .await?;

        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), socket.next()).await?;
        let Some(Ok(H3Message::Binary(enc_reply))) = reply else {
            anyhow::bail!("expected binary h3ws reply for {payload:?}, got {reply:?}");
        };
        let pkt = decrypt_udp_packet(std::slice::from_ref(&user), &enc_reply)?;
        let (_, consumed) = crate::protocol::parse_target_addr(&pkt.payload)?
            .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
        assert_eq!(&pkt.payload[consumed..], expected_reply);
        socket.send(H3Message::Close(None)).await?;
    }

    let peers = upstream_task.await??;
    assert_eq!(peers.len(), 2);
    assert_eq!(
        peers[0], peers[1],
        "NAT socket source port should stay stable across H3 WS reconnect"
    );

    driver.abort();
    server.abort();
    let _ = driver.await;
    let _ = server.await;
    Ok(())
}

fn ipv6_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
    )
}

fn sample_config(listen: SocketAddr) -> Config {
    sample_config_with_users(
        listen,
        vec![UserEntry {
            id: "bob".into(),
            password: "secret-b".into(),
            fwmark: None,
            method: None,
            ws_path_tcp: None,
            ws_path_udp: None,
        }],
    )
}

fn sample_config_with_users(listen: SocketAddr, users: Vec<UserEntry>) -> Config {
    Config {
        listen: Some(listen),
        ss_listen: None,
        tls_cert_path: None,
        tls_key_path: None,
        h3_listen: None,
        h3_cert_path: None,
        h3_key_path: None,
        metrics_listen: None,
        metrics_path: "/metrics".into(),
        prefer_ipv4_upstream: false,
            outbound_ipv6_prefix: None,
            outbound_ipv6_interface: None,
            outbound_ipv6_refresh_secs: 30,
        ws_path_tcp: "/tcp".into(),
        ws_path_udp: "/udp".into(),
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
        password: None,
        fwmark: None,
        users,
        method: CipherKind::Chacha20IetfPoly1305,
        tuning: Default::default(),
    }
}

fn basic_auth_header(password: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("ignored:{password}")))
}

fn set_cookie_pair<T>(response: &axum::http::Response<T>) -> Result<String> {
    Ok(response
        .headers()
        .get(header::SET_COOKIE)
        .context("missing set-cookie header")?
        .to_str()?
        .split(';')
        .next()
        .context("invalid set-cookie header")?
        .to_owned())
}

async fn send_encrypted_udp_request(
    client: &UdpSocket,
    listen_addr: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
    user: &crate::crypto::UserKey,
) -> Result<()> {
    let mut plaintext = TargetAddr::Socket(target).encode()?;
    plaintext.extend_from_slice(payload);
    let ciphertext = encrypt_udp_packet(user, &plaintext)?;
    client.send_to(&ciphertext, listen_addr).await?;
    Ok(())
}

async fn recv_decrypted_udp_response(
    client: &UdpSocket,
    user: &crate::crypto::UserKey,
) -> Result<Vec<u8>> {
    let mut encrypted_reply = [0_u8; 65_535];
    let (read, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut encrypted_reply),
    )
    .await??;

    let packet = decrypt_udp_packet(std::slice::from_ref(user), &encrypted_reply[..read])?;
    let (_, consumed) = crate::protocol::parse_target_addr(&packet.payload)?
        .ok_or_else(|| anyhow::anyhow!("missing target in udp response"))?;
    Ok(packet.payload[consumed..].to_vec())
}

fn test_h3_server_tls() -> Result<(rustls::ServerConfig, CertificateDer<'static>)> {
    super::ensure_rustls_provider_installed();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    Ok((tls_config, cert_der))
}

fn test_h3_client_config(cert_der: CertificateDer<'static>) -> Result<quinn::ClientConfig> {
    super::ensure_rustls_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

fn write_test_h2_tls_cert()
-> Result<(std::path::PathBuf, std::path::PathBuf, CertificateDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_pem = cert.cert.pem();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_pem = cert.signing_key.serialize_pem();
    let base = std::env::temp_dir().join(format!(
        "outline-ss-rust-h2-tls-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let cert_path = base.with_extension("crt.pem");
    let key_path = base.with_extension("key.pem");
    std::fs::write(&cert_path, cert_pem)?;
    std::fs::write(&key_path, key_pem)?;
    Ok((cert_path, key_path, cert_der))
}
