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
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    time::Duration,
};

use anyhow::{Result, bail};
use arc_swap::ArcSwap;
use axum::http::{Method, Request, StatusCode, Version, header};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use http_body_util::Empty;
use hyper::{client::conn::http2, ext::Protocol};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
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
use super::{sample_config, sample_config_with_users};
use crate::config::UserEntry;
use crate::crypto::{AeadStreamEncryptor, UserKey};
use crate::metrics::{Metrics, Transport};
use crate::protocol::{
    TargetAddr,
    vless::{COMMAND_TCP, VERSION as VLESS_VERSION, VlessUser, parse_uuid},
};

// ── Mock upstream ─────────────────────────────────────────────────────────────

/// Spins up a TCP echo server on a random localhost port and returns
/// `(addr, accept_counter)`. Each successful `accept` bumps the
/// counter before forking off the per-connection echo loop.
async fn spawn_echo_target() -> Result<(SocketAddr, Arc<AtomicUsize>)> {
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
    let task =
        tokio::spawn(async move { serve_listener(listener, app, ShutdownSignal::never()).await });
    Ok(ResumptionTestServer { listen_addr, task })
}

/// Single-user SS-over-WebSocket fixture: returns a running server and
/// the bob `UserKey` used by clients to encrypt SS-AEAD traffic.
async fn spawn_ss_resumption_server(
    config_mutator: impl FnOnce(&mut crate::config::Config),
) -> Result<(ResumptionTestServer, UserKey)> {
    // sample_config picks 0.0.0.0 — but we'll override `listen` after
    // bind anyway. The address here is only used to validate the
    // config schema.
    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config(dummy_listen);
    config.session_resumption.enabled = true;
    config_mutator(&mut config);
    let user = build_user_routes(&config)?[0].user.clone();
    let server = spawn_test_server(config, Vec::new()).await?;
    Ok((server, user))
}

/// Two-user SS-over-WebSocket fixture sharing the same default `/tcp`
/// path. Returns `(server, alice, bob)`. Used by the owner-mismatch
/// test to demonstrate that a Session ID issued to one user cannot be
/// claimed by the other even when they sit on the same route.
async fn spawn_ss_two_user_server() -> Result<(ResumptionTestServer, UserKey, UserKey)> {
    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config_with_users(
        dummy_listen,
        vec![
            UserEntry {
                id: "alice".into(),
                password: Some("secret-a".into()),
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                ws_path_vless: None,
                enabled: None,
            },
            UserEntry {
                id: "bob".into(),
                password: Some("secret-b".into()),
                fwmark: None,
                method: None,
                ws_path_tcp: None,
                ws_path_udp: None,
                vless_id: None,
                ws_path_vless: None,
                enabled: None,
            },
        ],
    );
    config.session_resumption.enabled = true;
    let routes = build_user_routes(&config)?;
    let alice = routes
        .iter()
        .find(|r| r.user.id() == "alice")
        .map(|r| r.user.clone())
        .ok_or_else(|| anyhow::anyhow!("missing alice"))?;
    let bob = routes
        .iter()
        .find(|r| r.user.id() == "bob")
        .map(|r| r.user.clone())
        .ok_or_else(|| anyhow::anyhow!("missing bob"))?;
    let server = spawn_test_server(config, Vec::new()).await?;
    Ok((server, alice, bob))
}

/// VLESS-over-WebSocket fixture mounted on `/vless`. Returns the
/// running server and the parsed `VlessUser` for client-side request
/// construction.
async fn spawn_vless_resumption_server() -> Result<(ResumptionTestServer, VlessUser)> {
    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config(dummy_listen);
    config.session_resumption.enabled = true;
    let vless_user = VlessUser::new("550e8400-e29b-41d4-a716-446655440000".into(), None)?;
    let vless_route = VlessUserRoute {
        user: vless_user.clone(),
        ws_path: Arc::from("/vless"),
    };
    let server = spawn_test_server(config, vec![vless_route]).await?;
    Ok((server, vless_user))
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

/// Encrypts a single SS-AEAD chunk: target address followed by
/// `payload`. Each invocation uses a fresh encryptor (and therefore
/// a fresh random salt), matching what a real client would do for
/// every new SS session — including the resume case, where the
/// server consumes the target bytes but ignores their value.
fn ss_handshake_frame(user: &UserKey, target: SocketAddr, payload: &[u8]) -> Result<Bytes> {
    let mut plaintext = TargetAddr::Socket(target).encode()?;
    plaintext.extend_from_slice(payload);
    let mut encryptor = AeadStreamEncryptor::new(user, None)?;
    let mut buf = BytesMut::new();
    encryptor.encrypt_chunk(&plaintext, &mut buf)?;
    Ok(buf.freeze())
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

/// Builds a VLESS TCP request: VERSION + UUID + opt_len(0) + cmd(TCP)
/// + port(BE16) + atype(0x01 IPv4) + IPv4 + payload. Mirrors
/// `vless_websocket_tcp_relay_smoke` in `tests/vless.rs`.
fn vless_tcp_request(
    uuid: &str,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Bytes> {
    let mut request = Vec::with_capacity(32 + payload.len());
    request.push(VLESS_VERSION);
    request.extend_from_slice(&parse_uuid(uuid)?);
    request.push(0); // opt_len: no addons
    request.push(COMMAND_TCP);
    request.extend_from_slice(&target.port().to_be_bytes());
    request.push(0x01); // IPv4
    let std::net::IpAddr::V4(ipv4) = target.ip() else {
        bail!("VLESS test request only constructs IPv4 targets");
    };
    request.extend_from_slice(&ipv4.octets());
    request.extend_from_slice(payload);
    Ok(Bytes::from(request))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ss_resume_hit_skips_fresh_upstream() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // Session #1: capable, no resume → minted ID, fresh upstream.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let session_id = issued.ok_or_else(|| {
        anyhow::anyhow!("server did not issue X-Outline-Session despite Resume-Capable")
    })?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"ping1")?))
        .await?;
    let _reply = expect_binary_reply(&mut socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2: capable + resume. Should re-attach to parked
    // upstream — counter must remain 1.
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"ping2")?))
        .await?;
    let _reply2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "resume hit must reuse parked upstream"
    );

    socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_resume_with_unknown_id_falls_through_to_fresh() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // Bogus ID never minted → miss → fresh connect.
    let bogus = SessionId::from_bytes([0xDE; 16]);
    let (mut socket, _) = connect_ws_h1(server.listen_addr, "/tcp", Some(bogus), true).await?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"hello")?))
        .await?;
    let _reply = expect_binary_reply(&mut socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_resume_owner_mismatch_does_not_leak_session_to_other_user() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (server, alice, bob) = spawn_ss_two_user_server().await?;

    // Alice opens, gets a Session ID, closes — server parks under alice.
    let (mut alice_socket, alice_issued) =
        connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let alice_id = alice_issued
        .ok_or_else(|| anyhow::anyhow!("server didn't mint Session ID for Alice"))?;
    alice_socket
        .send(WsMessage::Binary(ss_handshake_frame(&alice, target_addr, b"a-ping")?))
        .await?;
    let _ = expect_binary_reply(&mut alice_socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    alice_socket.close(None).await?;
    drop(alice_socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Bob attempts to claim Alice's parked session. Owner-check rejects
    // it; the relay falls through to a fresh connect to upstream. The
    // parked entry is left in the registry for Alice to reclaim later.
    let (mut bob_socket, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(alice_id), true).await?;
    bob_socket
        .send(WsMessage::Binary(ss_handshake_frame(&bob, target_addr, b"b-ping")?))
        .await?;
    let _ = expect_binary_reply(&mut bob_socket).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        2,
        "owner mismatch must NOT hand Alice's parked upstream to Bob"
    );
    bob_socket.close(None).await?;
    drop(bob_socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Alice can still reclaim her parked session — owner-mismatch
    // must have re-inserted it instead of evicting.
    let (mut alice_socket2, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(alice_id), true).await?;
    alice_socket2
        .send(WsMessage::Binary(ss_handshake_frame(&alice, target_addr, b"a-resume")?))
        .await?;
    let _ = expect_binary_reply(&mut alice_socket2).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        2,
        "Alice should still be able to resume her own parked session"
    );
    alice_socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_resume_across_h1_to_h2_transport_switch() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // Session #1 over HTTP/1.
    let (mut h1_socket, h1_issued) = connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let session_id = h1_issued
        .ok_or_else(|| anyhow::anyhow!("HTTP/1 server didn't mint Session ID"))?;
    h1_socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"h1-ping")?))
        .await?;
    let _ = expect_binary_reply(&mut h1_socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    h1_socket.close(None).await?;
    drop(h1_socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2 over HTTP/2 — the cross-transport path the feature
    // is designed for. Server should re-attach the parked upstream.
    let (mut h2_socket, h2_outcome) =
        connect_ws_h2(server.listen_addr, "/tcp", Some(session_id), true).await?;
    assert!(
        h2_outcome.issued_session_id.is_some(),
        "H2 reply must still echo a Session ID even on resume"
    );
    h2_socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"h2-ping")?))
        .await?;
    let _ = expect_binary_reply(&mut h2_socket).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "resume across H1→H2 must reuse the parked upstream"
    );
    h2_socket.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_resume_after_ttl_expiry_falls_through_to_fresh() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    // Force a short TTL so we don't have to wait for the default 30 s.
    let (server, user) = spawn_ss_resumption_server(|cfg| {
        cfg.session_resumption.orphan_ttl_tcp_secs = 1;
    })
    .await?;

    // Session #1: dial, park.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/tcp", None, true).await?;
    let session_id = issued.ok_or_else(|| anyhow::anyhow!("server didn't mint a Session ID"))?;
    socket
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"hi")?))
        .await?;
    let _ = expect_binary_reply(&mut socket).await?;
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    socket.close(None).await?;
    drop(socket);

    // Wait past the per-kind TTL. `take_for_resume` checks the
    // deadline directly; we don't need the periodic sweeper to run.
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/tcp", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(ss_handshake_frame(&user, target_addr, b"hi-again")?))
        .await?;
    let _ = expect_binary_reply(&mut socket2).await?;
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        2,
        "expired entry must be ignored and the relay must open a fresh upstream"
    );
    socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn vless_resume_hit_skips_fresh_upstream() -> Result<()> {
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let std::net::IpAddr::V4(_) = target_addr.ip() else {
        bail!("VLESS resume test requires an IPv4 target");
    };
    let (server, _user) = spawn_vless_resumption_server().await?;
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    // Session #1: open VLESS-WS, send handshake+payload, expect the
    // standard `[VERSION, 0x00]` response header followed by the
    // echoed payload.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/vless", None, true).await?;
    let session_id =
        issued.ok_or_else(|| anyhow::anyhow!("VLESS server didn't mint Session ID"))?;
    socket
        .send(WsMessage::Binary(vless_tcp_request(
            uuid, target_addr, b"ping",
        )?))
        .await?;
    let response_header = expect_binary_reply(&mut socket).await?;
    assert_eq!(response_header.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoed = expect_binary_reply(&mut socket).await?;
    assert_eq!(echoed.as_ref(), b"ping");
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);
    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2: resume. Server re-attaches the parked upstream and
    // emits another `[VERSION, 0x00]` so the client parser still sees
    // a valid VLESS handshake response.
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/vless", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(vless_tcp_request(
            uuid, target_addr, b"pong",
        )?))
        .await?;
    let response_header2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(response_header2.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoed2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(echoed2.as_ref(), b"pong");
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "VLESS resume hit must reuse the parked upstream"
    );
    socket2.close(None).await?;
    Ok(())
}

