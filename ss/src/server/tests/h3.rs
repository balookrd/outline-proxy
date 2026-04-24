use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use axum::http::{Method, Request, StatusCode, Version, header};
use futures_util::SinkExt;
use futures_util::StreamExt;
use h3::ext::Protocol as H3Protocol;
use quinn::Endpoint;
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, Message as H3Message, Role as H3Role,
    Stream as H3Stream, WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use super::super::nat::NatTable;
use super::super::setup::{VlessUserRoute, build_vless_transport_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, Services, UdpServices, UserKeySlice};
use super::super::{DnsCache, build_user_routes, serve_h3_server};
use super::{build_test_state, sample_config, test_h3_client_config, test_h3_server_tls};
use crate::metrics::Metrics;
use crate::protocol::vless::{COMMAND_TCP, VERSION, VlessUser, parse_uuid};

#[tokio::test]
async fn websocket_rfc9220_http3_connect_smoke() -> Result<()> {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let server =
        H3WebSocketServer::<H3Transport>::bind(server_addr, tls_config, H3WsConfig::default())
            .await?;
    let addr = server.local_addr()?;

    let config = sample_config(addr);
    let user_routes = build_user_routes(&config)?;
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
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
async fn vless_websocket_http3_tcp_relay_smoke() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(request)
    });

    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = test_h3_server_tls()?;
    let server =
        H3WebSocketServer::<H3Transport>::bind(server_addr, tls_config, H3WsConfig::default())
            .await?;
    let addr = server.local_addr()?;

    let config = sample_config(addr);
    let metrics = Metrics::new(&config);
    let vless_user = VlessUser::new("550e8400-e29b-41d4-a716-446655440000".into(), None)?;
    let vless_routes = Arc::new(build_vless_transport_route_map(&[VlessUserRoute {
        user: vless_user,
        ws_path: Arc::from("/vless"),
    }]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
    }));
    let services = Arc::new(Services {
        metrics,
        dns_cache: DnsCache::new(std::time::Duration::from_secs(30)),
        prefer_ipv4_upstream: false,
        outbound_ipv6: None,
        udp: UdpServices {
            nat_table: NatTable::new(std::time::Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(
                std::time::Duration::from_secs(300),
                0,
            ),
            relay_semaphore: None,
        },
    });
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<crate::crypto::UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let server_task = tokio::spawn(async move {
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
        .uri(format!("https://localhost:{}/vless", addr.port()))
        .version(Version::HTTP_3)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .extension(H3Protocol::WEBSOCKET)
        .body(())?;

    let mut stream = send_request.send_request(request).await?;
    let response = stream.recv_response().await?;
    assert_eq!(response.status(), StatusCode::OK);

    let h3_stream = H3Stream::<H3Transport>::from_h3_client(stream);
    let mut socket = H3WebSocketStream::from_raw(h3_stream, H3Role::Client, H3WsConfig::default());

    let mut payload = Vec::new();
    payload.push(VERSION);
    payload.extend_from_slice(&parse_uuid("550e8400-e29b-41d4-a716-446655440000")?);
    payload.push(0);
    payload.push(COMMAND_TCP);
    payload.extend_from_slice(&upstream_addr.port().to_be_bytes());
    payload.push(0x01);
    payload.extend_from_slice(&[127, 0, 0, 1]);
    payload.extend_from_slice(b"ping");
    socket.send(H3Message::Binary(payload.into())).await?;

    let response_header = match socket.next().await {
        Some(Ok(H3Message::Binary(bytes))) => bytes,
        other => anyhow::bail!("missing vless response header: {other:?}"),
    };
    assert_eq!(response_header.as_ref(), &[VERSION, 0x00]);

    let reply = match socket.next().await {
        Some(Ok(H3Message::Binary(bytes))) => bytes,
        other => anyhow::bail!("missing vless upstream reply: {other:?}"),
    };
    assert_eq!(reply.as_ref(), b"pong");

    socket.send(H3Message::Close(None)).await?;
    assert_eq!(upstream_task.await??, *b"ping");

    driver.abort();
    server_task.abort();
    let _ = driver.await;
    let _ = server_task.await;
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
    let user_routes = build_user_routes(&config)?;
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
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
    let user_routes = build_user_routes(&config)?;
    let metrics = Metrics::new(&config);
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
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
