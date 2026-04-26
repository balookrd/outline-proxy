//! End-to-end smoke tests for cross-transport session resumption.
//!
//! These tests boot a real outline-ss-rust HTTP/1 WebSocket listener
//! with `[session_resumption] enabled = true`, dial it from a manual
//! `tokio_tungstenite` client, and assert two things on the wire:
//!
//! 1. The first connect (`Resume-Capable: 1`) yields a non-empty
//!    `X-Outline-Session` response header.
//! 2. A second connect carrying `Resume: <id>` re-attaches to the
//!    parked upstream — observable via a per-target accept counter
//!    that does not increment on the resumed session.
//!
//! The mock upstream is a TCP echo server with an `Arc<AtomicUsize>`
//! accept counter; a fresh `connect_tcp_target` on the server would
//! bump it, while a resume hit short-circuits before the connect.

use std::{
    net::Ipv4Addr,
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    time::Duration,
};

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        Message as WsMessage,
        client::IntoClientRequest,
        http::HeaderValue,
    },
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::resumption::{OrphanRegistry, ResumptionConfig, SessionId};
use super::super::shutdown::ShutdownSignal;
use super::super::state::UserKeySlice;
use super::super::{
    AuthPolicy, DnsCache, RouteRegistry, Services, UdpServices, build_transport_route_map,
    build_user_routes, build_app, user_keys,
};
use super::sample_config;
use crate::crypto::AeadStreamEncryptor;
use crate::metrics::{Metrics, Transport};
use crate::protocol::TargetAddr;

/// Spins up a TCP echo server on a random localhost port and returns
/// `(addr, accept_counter)`. Each successful `accept` bumps the
/// counter before forking off the per-connection echo loop.
async fn spawn_echo_target() -> Result<(std::net::SocketAddr, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        },
                        Err(_) => break,
                    }
                }
            });
        }
    });
    Ok((addr, counter))
}

#[tokio::test]
async fn websocket_tcp_resume_hit_skips_fresh_upstream() -> Result<()> {
    // ── 1. Mock upstream target (echo + accept counter) ───────────────
    let (target_addr, target_accepts) = spawn_echo_target().await?;

    // ── 2. Outline-SS server with resumption enabled ──────────────────
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;

    let mut config = sample_config(listen_addr);
    config.session_resumption.enabled = true;

    let user_routes = build_user_routes(&config)?;
    let user = user_routes[0].user.clone();

    let metrics = Metrics::new(&config);
    let orphan_registry = Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&config.session_resumption),
        Arc::clone(&metrics),
    ));

    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));

    let users = user_keys(user_routes.as_ref());
    let tcp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Udp));
    let vless_routes = Arc::new(super::super::setup::build_vless_transport_route_map(&[]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: tcp_routes,
        udp: udp_routes,
        vless: vless_routes,
    }));
    let services = Arc::new(Services::new(
        Arc::clone(&metrics),
        dns_cache,
        false,
        None,
        UdpServices {
            nat_table,
            replay_store: super::super::replay::ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        Some(orphan_registry),
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
    });
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    // ── 3. First WS connect: advertise Resume-Capable, capture ID ─────
    let mut req = format!("ws://{listen_addr}/tcp").into_client_request()?;
    req.headers_mut()
        .insert("x-outline-resume-capable", HeaderValue::from_static("1"));
    let (mut socket, response) = connect_async(req).await?;
    let session_id = response
        .headers()
        .get("x-outline-session")
        .and_then(|v| v.to_str().ok())
        .and_then(SessionId::parse_hex)
        .ok_or_else(|| anyhow::anyhow!(
            "server did not issue X-Outline-Session despite Resume-Capable"
        ))?;

    // SS-AEAD handshake: encrypt target_addr + "ping1" under the user's key.
    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"ping1");
    let mut encryptor = AeadStreamEncryptor::new(&user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf)?;
    socket.send(WsMessage::Binary(buf.freeze())).await?;

    // Wait for an encrypted echo back. We don't need to decrypt it —
    // its arrival proves the server reached the upstream and pumped
    // bytes back through the relay.
    let reply = tokio::time::timeout(Duration::from_secs(2), socket.next()).await?;
    if !matches!(reply, Some(Ok(WsMessage::Binary(_)))) {
        bail!("expected encrypted binary reply on first session, got {reply:?}");
    }
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "first session should have triggered exactly one fresh upstream connect"
    );

    // Close the WS to make the server park the upstream.
    socket.close(None).await?;
    drop(socket);
    // Give the server a moment to observe Close, run park-on-drop, and
    // commit the entry into the orphan registry. The path is sub-
    // millisecond in healthy cases; 150 ms is generous slack for CI.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ── 4. Second WS connect: present Resume — expect resume hit ──────
    let mut req = format!("ws://{listen_addr}/tcp").into_client_request()?;
    req.headers_mut()
        .insert("x-outline-resume-capable", HeaderValue::from_static("1"));
    req.headers_mut().insert(
        "x-outline-resume",
        HeaderValue::from_str(&session_id.to_hex())?,
    );
    let (mut socket2, _response2) = connect_async(req).await?;

    // Fresh encryptor — VLESS would skip the target on a hit but SS
    // re-runs `parse_target_addr` because the AEAD stream prefix
    // carries the bytes regardless. The server consumes them and
    // ignores the address (the parked one is authoritative).
    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"ping2");
    let mut encryptor = AeadStreamEncryptor::new(&user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf)?;
    socket2.send(WsMessage::Binary(buf.freeze())).await?;

    let reply2 = tokio::time::timeout(Duration::from_secs(2), socket2.next()).await?;
    if !matches!(reply2, Some(Ok(WsMessage::Binary(_)))) {
        bail!("expected encrypted binary reply on resumed session, got {reply2:?}");
    }

    // Critical e2e assertion: the upstream should NOT have been opened
    // again. A miss would re-run `connect_tcp_target` and bump the
    // counter to 2.
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "resume hit must reuse parked upstream — fresh accept on target indicates miss"
    );

    socket2.close(None).await?;
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn websocket_tcp_resume_with_unknown_id_starts_fresh_session() -> Result<()> {
    // Negative path: a client presenting a Session ID the server has
    // never minted (e.g. cache poisoning, restart between sessions)
    // must result in a fresh upstream connect, not a hung handshake.
    let (target_addr, target_accepts) = spawn_echo_target().await?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;

    let mut config = sample_config(listen_addr);
    config.session_resumption.enabled = true;

    let user_routes = build_user_routes(&config)?;
    let user = user_routes[0].user.clone();

    let metrics = Metrics::new(&config);
    let orphan_registry = Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&config.session_resumption),
        Arc::clone(&metrics),
    ));

    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));

    let users = user_keys(user_routes.as_ref());
    let tcp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Udp));
    let vless_routes = Arc::new(super::super::setup::build_vless_transport_route_map(&[]));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: tcp_routes,
        udp: udp_routes,
        vless: vless_routes,
    }));
    let services = Arc::new(Services::new(
        Arc::clone(&metrics),
        dns_cache,
        false,
        None,
        UdpServices {
            nat_table,
            replay_store: super::super::replay::ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        Some(orphan_registry),
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
    });
    let app = build_app(routes, services, auth);
    let server =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });

    // Connect with a wholly bogus Session ID — never been minted, never
    // owned by any user. The server should fall through to the
    // standard fresh-connect path.
    let bogus = SessionId::from_bytes([0xDE; 16]);
    let mut req = format!("ws://{listen_addr}/tcp").into_client_request()?;
    req.headers_mut()
        .insert("x-outline-resume-capable", HeaderValue::from_static("1"));
    req.headers_mut().insert(
        "x-outline-resume",
        HeaderValue::from_str(&bogus.to_hex())?,
    );
    let (mut socket, _response) = connect_async(req).await?;

    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"hello");
    let mut encryptor = AeadStreamEncryptor::new(&user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf)?;
    socket.send(WsMessage::Binary(buf.freeze())).await?;

    let reply = tokio::time::timeout(Duration::from_secs(2), socket.next()).await?;
    if !matches!(reply, Some(Ok(WsMessage::Binary(_)))) {
        bail!("expected encrypted binary reply after miss-fallback, got {reply:?}");
    }
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "miss-then-fresh-connect: the upstream should be opened exactly once"
    );

    socket.close(None).await?;
    server.abort();
    let _ = server.await;
    Ok(())
}
