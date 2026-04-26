use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::setup::{VlessUserRoute, build_vless_transport_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, Services, UdpServices, UserKeySlice};
use super::super::{DnsCache, build_app};
use arc_swap::ArcSwap;
use super::sample_config;
use crate::metrics::Metrics;
use crate::protocol::vless::{COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, VERSION, VlessUser, parse_uuid};
use crate::protocol::vless_mux::{
    OPTION_DATA, ParsedFrame, SessionStatus, encode_frame, parse_frame,
};
use crate::protocol::TargetAddr;
use bytes::BytesMut;

#[tokio::test]
async fn vless_websocket_tcp_relay_smoke() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(request)
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
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
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(Vec::<crate::crypto::UserKey>::new().into_boxed_slice())))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let (mut socket, _) = connect_async(format!("ws://{listen_addr}/vless")).await?;
    let mut request = Vec::new();
    request.push(VERSION);
    request.extend_from_slice(&parse_uuid("550e8400-e29b-41d4-a716-446655440000")?);
    request.push(0);
    request.push(COMMAND_TCP);
    request.extend_from_slice(&upstream_addr.port().to_be_bytes());
    request.push(0x01);
    request.extend_from_slice(&[127, 0, 0, 1]);
    request.extend_from_slice(b"ping");
    socket.send(WsMessage::Binary(request.into())).await?;

    let Some(Ok(WsMessage::Binary(response_header))) = socket.next().await else {
        anyhow::bail!("missing vless response header");
    };
    assert_eq!(response_header.as_ref(), &[VERSION, 0x00]);

    let Some(Ok(WsMessage::Binary(reply))) = socket.next().await else {
        anyhow::bail!("missing vless upstream reply");
    };
    assert_eq!(reply.as_ref(), b"pong");
    socket.close(None).await?;

    assert_eq!(upstream_task.await??, *b"ping");
    server.abort();
    Ok(())
}

#[tokio::test]
async fn vless_websocket_udp_relay_smoke() -> Result<()> {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0_u8; 1500];
        let (n, peer) = upstream.recv_from(&mut buf).await?;
        let received = buf[..n].to_vec();
        upstream.send_to(b"pong", peer).await?;
        Result::<_, anyhow::Error>::Ok(received)
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
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
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(Vec::<crate::crypto::UserKey>::new().into_boxed_slice())))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let (mut socket, _) = connect_async(format!("ws://{listen_addr}/vless")).await?;
    let mut frame = Vec::new();
    frame.push(VERSION);
    frame.extend_from_slice(&parse_uuid("550e8400-e29b-41d4-a716-446655440000")?);
    frame.push(0);
    frame.push(COMMAND_UDP);
    frame.extend_from_slice(&upstream_addr.port().to_be_bytes());
    frame.push(0x01);
    frame.extend_from_slice(&[127, 0, 0, 1]);
    let payload: &[u8] = b"ping";
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    socket.send(WsMessage::Binary(frame.into())).await?;

    let Some(Ok(WsMessage::Binary(response_header))) = socket.next().await else {
        anyhow::bail!("missing vless response header");
    };
    assert_eq!(response_header.as_ref(), &[VERSION, 0x00]);

    let Some(Ok(WsMessage::Binary(reply))) = socket.next().await else {
        anyhow::bail!("missing vless upstream udp reply");
    };
    assert_eq!(reply.len(), 2 + 4);
    let reply_len = u16::from_be_bytes([reply[0], reply[1]]) as usize;
    assert_eq!(reply_len, 4);
    assert_eq!(&reply[2..], b"pong");
    socket.close(None).await?;

    assert_eq!(upstream_task.await??, b"ping");
    server.abort();
    Ok(())
}

#[tokio::test]
async fn vless_websocket_accepts_large_initial_frame() -> Result<()> {
    const PAYLOAD_LEN: usize = 2048;

    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut request = vec![0_u8; PAYLOAD_LEN];
        stream.read_exact(&mut request).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(request)
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
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
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(Vec::<crate::crypto::UserKey>::new().into_boxed_slice())))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let (mut socket, _) = connect_async(format!("ws://{listen_addr}/vless")).await?;
    let mut request = Vec::new();
    request.push(VERSION);
    request.extend_from_slice(&parse_uuid("550e8400-e29b-41d4-a716-446655440000")?);
    request.push(0);
    request.push(COMMAND_TCP);
    request.extend_from_slice(&upstream_addr.port().to_be_bytes());
    request.push(0x01);
    request.extend_from_slice(&[127, 0, 0, 1]);
    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();
    request.extend_from_slice(&payload);
    socket.send(WsMessage::Binary(request.into())).await?;

    let Some(Ok(WsMessage::Binary(response_header))) = socket.next().await else {
        anyhow::bail!("missing vless response header");
    };
    assert_eq!(response_header.as_ref(), &[VERSION, 0x00]);

    let Some(Ok(WsMessage::Binary(reply))) = socket.next().await else {
        anyhow::bail!("missing vless upstream reply");
    };
    assert_eq!(reply.as_ref(), b"pong");
    socket.close(None).await?;

    assert_eq!(upstream_task.await??, payload);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn vless_websocket_mux_tcp_relay_smoke() -> Result<()> {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_addr = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        stream.write_all(b"pong").await?;
        Result::<_, anyhow::Error>::Ok(request)
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
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
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<crate::crypto::UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let (mut socket, _) = connect_async(format!("ws://{listen_addr}/vless")).await?;

    // VLESS MUX request header. Per mux.cool, the target host is the literal
    // "v1.mux.cool" with port 0; real sub-connection targets ride inside the
    // mux New frames that follow.
    let mut request = Vec::new();
    request.push(VERSION);
    request.extend_from_slice(&parse_uuid("550e8400-e29b-41d4-a716-446655440000")?);
    request.push(0);
    request.push(COMMAND_MUX);
    request.extend_from_slice(&0_u16.to_be_bytes());
    request.push(0x02);
    let domain = b"v1.mux.cool";
    request.push(domain.len() as u8);
    request.extend_from_slice(domain);

    let mut new_frame = BytesMut::new();
    let target =
        TargetAddr::Socket(std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, upstream_addr.port())));
    encode_frame(
        &mut new_frame,
        1,
        SessionStatus::New,
        OPTION_DATA,
        Some(crate::protocol::vless_mux::Network::Tcp),
        Some(&target),
        Some(b"ping"),
    );
    request.extend_from_slice(&new_frame);
    socket.send(WsMessage::Binary(request.into())).await?;

    let Some(Ok(WsMessage::Binary(response_header))) = socket.next().await else {
        anyhow::bail!("missing vless mux response header");
    };
    assert_eq!(response_header.as_ref(), &[VERSION, 0x00]);

    let Some(Ok(WsMessage::Binary(reply))) = socket.next().await else {
        anyhow::bail!("missing mux upstream reply frame");
    };
    let ParsedFrame { meta, data, consumed } =
        parse_frame(&reply)?.expect("complete mux frame in single binary message");
    assert_eq!(consumed, reply.len());
    assert_eq!(meta.session_id, 1);
    assert_eq!(meta.status, SessionStatus::Keep);
    assert_eq!(data, Some(b"pong".as_ref()));

    socket.close(None).await?;
    assert_eq!(upstream_task.await??, *b"ping");
    server.abort();
    Ok(())
}

/// Active-probe regression: a VLESS request with the wrong version byte
/// must be answered with a graceful WebSocket Close frame, not an abrupt
/// channel drop.  Pre-fix the writer task exited silently on parser error,
/// leaving the peer with an unsignalled FIN/RST that probes can use to
/// fingerprint VLESS apart from a benign WebSocket endpoint (which always
/// terminates with an RFC 6455 Close).  Mirrors the SS auth-failure path.
#[tokio::test]
async fn vless_websocket_invalid_version_replies_with_close_frame() -> Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;
    let config = sample_config(listen_addr);
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
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<crate::crypto::UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    let (mut socket, _) = connect_async(format!("ws://{listen_addr}/vless")).await?;

    let mut probe = Vec::new();
    probe.push(0x01); // wrong VLESS version — parser bails on InvalidVersion
    probe.extend_from_slice(&[0_u8; 16]);
    probe.push(0); // opt_len
    probe.push(COMMAND_TCP);
    probe.extend_from_slice(&443_u16.to_be_bytes());
    probe.push(0x01);
    probe.extend_from_slice(&[127, 0, 0, 1]);
    socket.send(WsMessage::Binary(probe.into())).await?;

    let next = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting for vless close frame"))?;
    match next {
        Some(Ok(WsMessage::Close(_))) => {},
        other => anyhow::bail!(
            "expected graceful Close frame on invalid vless version, got: {other:?}"
        ),
    }

    server.abort();
    Ok(())
}
