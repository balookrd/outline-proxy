use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::setup::{VlessUserRoute, build_vless_transport_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::{AuthPolicy, RouteRegistry, Services, UdpServices};
use super::super::{DnsCache, build_app};
use super::sample_config;
use crate::metrics::Metrics;
use crate::protocol::vless::{COMMAND_TCP, VERSION, VlessUser, parse_uuid};

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
    let routes = Arc::new(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
    });
    let services = Arc::new(Services {
        metrics,
        dns_cache: DnsCache::new(std::time::Duration::from_secs(30)),
        prefer_ipv4_upstream: false,
        outbound_ipv6: None,
        udp: UdpServices {
            nat_table: NatTable::new(std::time::Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(std::time::Duration::from_secs(
                300,
            )),
            relay_semaphore: None,
        },
    });
    let auth = Arc::new(AuthPolicy {
        users: Arc::from(Vec::<crate::crypto::UserKey>::new().into_boxed_slice()),
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
    let routes = Arc::new(RouteRegistry {
        tcp: Arc::new(BTreeMap::new()),
        udp: Arc::new(BTreeMap::new()),
        vless: vless_routes,
    });
    let services = Arc::new(Services {
        metrics,
        dns_cache: DnsCache::new(std::time::Duration::from_secs(30)),
        prefer_ipv4_upstream: false,
        outbound_ipv6: None,
        udp: UdpServices {
            nat_table: NatTable::new(std::time::Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(std::time::Duration::from_secs(
                300,
            )),
            relay_semaphore: None,
        },
    });
    let auth = Arc::new(AuthPolicy {
        users: Arc::from(Vec::<crate::crypto::UserKey>::new().into_boxed_slice()),
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
