//! End-to-end smoke tests for cross-transport session resumption.
//!
//! These tests boot a real outline-ss-rust HTTP/1 (and, in the
//! cross-transport case, HTTP/2) WebSocket listener with
//! `[session_resumption] enabled = true`, dial it from a manual
//! `tokio_tungstenite` / `hyper` client, and assert resumption
//! observably on the wire.
//!
//! The mock upstream is a TCP echo server with an
//! `Arc<AtomicUsize>` accept counter — a fresh `connect_tcp_target`
//! on the server bumps it, while a resume hit short-circuits before
//! the connect. The counter is the load-bearing signal of every
//! test in this file.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use axum::http::{Method, Request, StatusCode, Version, header};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::Empty;
use hyper::{client::conn::http2, ext::Protocol};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Mutex,
    task::JoinHandle,
};
use tokio_tungstenite::{
    WebSocketStream, connect_async,
    tungstenite::{
        Message as WsMessage, client::IntoClientRequest, http::HeaderValue, protocol,
    },
};

use super::super::bootstrap::serve_listener;
use super::super::nat::NatTable;
use super::super::resumption::{OrphanRegistry, ResumptionConfig, SessionId};
use super::super::setup::{VlessUserRoute, build_vless_transport_route_map};
use super::super::shutdown::ShutdownSignal;
use super::super::state::UserKeySlice;
use super::super::{
    AuthPolicy, DnsCache, RouteRegistry, Services, UdpServices, build_transport_route_map,
    build_user_routes, build_app, user_keys,
};
use crate::metrics::{Metrics, Transport};

mod raw_quic;
mod ss;
mod vless;

// ── Mock upstream ─────────────────────────────────────────────────────────────

/// Spins up a UDP echo server on a random localhost port and returns
/// `(addr, unique_sources)`. Each datagram is echoed straight back
/// to the sender; the `unique_sources` set tracks every distinct
/// source `SocketAddr` ever observed.
///
/// This is the UDP analogue of [`spawn_echo_target`]'s accept
/// counter: the number of unique sources is `1` while the server
/// reuses one parked `UdpSocket`, and `2` after a fresh
/// `bind_and_connect_udp` allocates a new ephemeral port.
async fn spawn_echo_udp_target() -> Result<(SocketAddr, Arc<Mutex<std::collections::HashSet<SocketAddr>>>)> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = socket.local_addr()?;
    let sources = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let sources_clone = Arc::clone(&sources);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    sources_clone.lock().await.insert(src);
                    let _ = socket.send_to(&buf[..n], src).await;
                },
                Err(_) => break,
            }
        }
    });
    Ok((addr, sources))
}

/// Spins up a TCP echo server on a random localhost port and returns
/// `(addr, accept_counter)`. Each successful `accept` bumps the
/// counter before forking off the per-connection echo loop.
async fn spawn_echo_target() -> Result<(SocketAddr, Arc<AtomicUsize>)> {
    use std::sync::atomic::Ordering;
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

// ── Server harness ────────────────────────────────────────────────────────────

/// A running outline-ss-rust test server with cross-transport
/// resumption enabled. Aborts the underlying tokio task on drop so
/// tests don't leak listeners between cases.
struct ResumptionTestServer {
    listen_addr: SocketAddr,
    task: JoinHandle<Result<()>>,
    metrics: Arc<Metrics>,
}

impl Drop for ResumptionTestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Builds the full app state from a parsed `Config` (and optional VLESS
/// route table) and starts serving on a fresh random localhost port.
/// Caller-supplied `mutator` runs against the default `sample_config`
/// to flip the resumption flag and tweak TTL / caps as needed.
async fn spawn_test_server(
    config: crate::config::Config,
    vless_routes: Vec<VlessUserRoute>,
) -> Result<ResumptionTestServer> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let listen_addr = listener.local_addr()?;

    let user_routes = build_user_routes(&config)?;
    let users = user_keys(user_routes.as_ref());

    let metrics = Metrics::new(&config);
    let orphan_registry = Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&config.session_resumption),
        Arc::clone(&metrics),
    ));

    let nat_table = NatTable::new(Duration::from_secs(300));
    let dns_cache = DnsCache::new(Duration::from_secs(30));

    let tcp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(user_routes.as_ref(), Transport::Udp));
    let vless_table = Arc::new(build_vless_transport_route_map(&vless_routes));
    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: tcp_routes,
        udp: udp_routes,
        vless: vless_table,
        xhttp_vless: Arc::new(std::collections::BTreeMap::new()),
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
        16,
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(users))),
        http_root_auth: false,
        http_root_realm: "Authorization required".into(),
    });
    let app = build_app(routes, services, auth, None);
    let metrics_for_handle = Arc::clone(&metrics);
    let task =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });
    Ok(ResumptionTestServer {
        listen_addr,
        task,
        metrics: metrics_for_handle,
    })
}

// ── Client helpers ────────────────────────────────────────────────────────────

/// HTTP/1 WebSocket connect with optional `X-Outline-Resume` /
/// `X-Outline-Resume-Capable` headers. Returns the open socket and
/// the Session ID the server returned in `X-Outline-Session`.
async fn connect_ws_h1(
    listen_addr: SocketAddr,
    path: &str,
    resume: Option<SessionId>,
    capable: bool,
) -> Result<(
    WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Option<SessionId>,
)> {
    let mut req = format!("ws://{listen_addr}{path}").into_client_request()?;
    if capable {
        req.headers_mut()
            .insert("x-outline-resume-capable", HeaderValue::from_static("1"));
    }
    if let Some(id) = resume {
        req.headers_mut()
            .insert("x-outline-resume", HeaderValue::from_str(&id.to_hex())?);
    }
    let (socket, response) = connect_async(req).await?;
    let issued = response
        .headers()
        .get("x-outline-session")
        .and_then(|v| v.to_str().ok())
        .and_then(SessionId::parse_hex);
    Ok((socket, issued))
}

/// Wire-level outcome of the HTTP/2 CONNECT WebSocket handshake.
/// Returned by [`connect_ws_h2`] alongside the upgraded socket.
struct H2HandshakeOutcome {
    issued_session_id: Option<SessionId>,
    /// JoinHandle for the hyper HTTP/2 driver task; abort on drop so the
    /// driver does not outlive the test.
    _driver: JoinHandle<()>,
}

/// HTTP/2 (RFC 8441) WebSocket CONNECT to `listen_addr`. Mirrors
/// [`connect_ws_h1`]: optional resume headers, returns the upgraded
/// socket and the issued Session ID. Used only by the cross-transport
/// test, so the driver-task plumbing is local to this module.
async fn connect_ws_h2(
    listen_addr: SocketAddr,
    path: &str,
    resume: Option<SessionId>,
    capable: bool,
) -> Result<(
    WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>,
    H2HandshakeOutcome,
)> {
    let tcp = tokio::net::TcpStream::connect(listen_addr).await?;
    let (mut send_request, conn) = http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Empty<Bytes>>(TokioIo::new(tcp))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://{listen_addr}{path}"))
        .version(Version::HTTP_2)
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .extension(Protocol::from_static("websocket"));
    if capable {
        request = request.header("x-outline-resume-capable", "1");
    }
    if let Some(id) = resume {
        request = request.header("x-outline-resume", id.to_hex());
    }
    let request = request.body(Empty::<Bytes>::new())?;

    let mut response = send_request.send_request(request).await?;
    if response.status() != StatusCode::OK {
        bail!("HTTP/2 CONNECT returned status {}", response.status());
    }
    let issued = response
        .headers()
        .get("x-outline-session")
        .and_then(|v| v.to_str().ok())
        .and_then(SessionId::parse_hex);

    let upgraded = hyper::upgrade::on(&mut response).await?;
    let socket =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), protocol::Role::Client, None)
            .await;
    Ok((
        socket,
        H2HandshakeOutcome {
            issued_session_id: issued,
            _driver: driver,
        },
    ))
}

/// Reads exactly one binary message from the WebSocket within 2 s.
/// Returns the encrypted bytes verbatim — the tests do not decrypt
/// the reply because the on-the-wire arrival of any binary frame is
/// already proof that the relay completed (with or without resume).
async fn expect_binary_reply<S>(socket: &mut S) -> Result<Bytes>
where
    S: futures_util::Stream<
            Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let next = tokio::time::timeout(Duration::from_secs(2), socket.next()).await?;
    match next {
        Some(Ok(WsMessage::Binary(bytes))) => Ok(bytes),
        other => bail!("expected encrypted binary reply, got {other:?}"),
    }
}
