use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Result;
use axum::http::{Method, Request, StatusCode, Version, header};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use h3::ext::Protocol as H3Protocol;
use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper::ext::Protocol;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use quinn::Endpoint;
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, Message as H3Message, Role as H3Role,
    Stream as H3Stream, WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
};
use tokio::net::{TcpListener, UdpSocket};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message as WsMessage, protocol},
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::shutdown::ShutdownSignal;
use super::super::{
    DnsCache, Services, SsUdpCtx, UdpServices, build_app, build_user_routes, build_users,
    serve_h3_server, serve_ss_udp_socket,
};
use super::{
    build_test_state, recv_decrypted_udp_response, sample_config, send_encrypted_udp_request,
    test_h3_client_config, test_h3_server_tls,
};
use crate::crypto::{decrypt_udp_packet, encrypt_udp_packet};
use crate::metrics::Metrics;
use crate::protocol::TargetAddr;

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
    let services = Arc::new(Services::new(
        metrics,
        DnsCache::new(std::time::Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: NatTable::new(std::time::Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(
                std::time::Duration::from_secs(300),
                0,
            ),
            relay_semaphore: None,
        },
        None,
        16,
    ));
    let ctx = SsUdpCtx { users, services };
    let server =
        tokio::spawn(
            async move { serve_ss_udp_socket(listener, ctx, ShutdownSignal::never()).await },
        );

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
            let reply = if expected == b"ping-1" {
                b"pong-1".as_slice()
            } else {
                b"pong-2".as_slice()
            };
            upstream.send_to(reply, peer).await?;
        }
        Result::<_, anyhow::Error>::Ok(peers)
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let config = sample_config(addr);
    let user_routes = build_user_routes(&config)?;
    let user = user_routes[0].user.clone();
    let nat_table = NatTable::new(std::time::Duration::from_secs(300));
    let dns_cache = DnsCache::new(std::time::Duration::from_secs(30));
    let (routes, services, auth) = build_test_state(
        user_routes,
        Metrics::new(&config),
        nat_table,
        dns_cache,
        false,
        "Authorization required",
    );
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let (mut send_request, conn) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .handshake::<_, Empty<Bytes>>(TokioIo::new(tcp))
        .await?;
    let driver = tokio::spawn(conn);

    for (payload, expected_reply) in
        [(b"ping-1".as_slice(), b"pong-1".as_slice()), (b"ping-2".as_slice(), b"pong-2".as_slice())]
    {
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
        let mut socket =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), protocol::Role::Client, None)
                .await;

        let mut plaintext = TargetAddr::Socket(upstream_addr).encode()?;
        plaintext.extend_from_slice(payload);
        socket
            .send(WsMessage::Binary(encrypt_udp_packet(&user, &plaintext)?.into()))
            .await?;

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
    assert_eq!(
        peers[0], peers[1],
        "NAT socket source port should stay stable across WS reconnect"
    );

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
            let reply = if expected == b"ping-1" {
                b"pong-1".as_slice()
            } else {
                b"pong-2".as_slice()
            };
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
    let user_routes = build_user_routes(&config)?;
    let user = user_routes[0].user.clone();
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
        serve_h3_server(
            server,
            routes,
            services,
            auth,
            std::sync::Arc::from(vec![crate::config::H3Alpn::H3].into_boxed_slice()),
            std::sync::Arc::from(Vec::<crate::protocol::vless::VlessUser>::new().into_boxed_slice()),
            std::sync::Arc::from(Vec::<std::sync::Arc<str>>::new().into_boxed_slice()),
            std::sync::Arc::from(Vec::<crate::crypto::UserKey>::new().into_boxed_slice()),
            ShutdownSignal::never(),
        )
        .await
    });

    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(test_h3_client_config(cert_der)?);

    let connection = endpoint.connect(addr, "localhost")?.await?;
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(connection)).await?;
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    for (payload, expected_reply) in
        [(b"ping-1".as_slice(), b"pong-1".as_slice()), (b"ping-2".as_slice(), b"pong-2".as_slice())]
    {
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
