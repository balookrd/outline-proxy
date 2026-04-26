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
use super::{sample_config, sample_config_with_users};
use crate::config::UserEntry;
use crate::crypto::{AeadStreamEncryptor, UserKey, encrypt_udp_packet};
use crate::metrics::{Metrics, Transport};
use crate::protocol::{
    TargetAddr,
    vless::{
        ADDON_TAG_RESUME_CAPABLE, ADDON_TAG_RESUME_ID, ADDON_TAG_RESUME_RESULT,
        ADDON_TAG_SESSION_ID, COMMAND_MUX, COMMAND_TCP, COMMAND_UDP, VERSION as VLESS_VERSION,
        VlessUser, parse_uuid,
    },
    vless_mux::{
        Network as MuxNetwork, OPTION_DATA, ParsedFrame, SessionStatus, encode_frame, parse_frame,
    },
};
use bytes::BufMut;

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

/// Builds a VLESS UDP request: VERSION + UUID + opt_len(0) + cmd(UDP)
/// + port(BE16) + atype(0x01 IPv4) + IPv4. The first datagram payload
/// is appended length-prefixed (`len:u16 + bytes`) — same wire format
/// the server expects for subsequent datagrams.
fn vless_udp_request(uuid: &str, target: SocketAddr, payload: &[u8]) -> Result<Bytes> {
    let mut request = BytesMut::with_capacity(32 + payload.len());
    request.put_u8(VLESS_VERSION);
    request.extend_from_slice(&parse_uuid(uuid)?);
    request.put_u8(0);
    request.put_u8(COMMAND_UDP);
    request.extend_from_slice(&target.port().to_be_bytes());
    request.put_u8(0x01);
    let std::net::IpAddr::V4(ipv4) = target.ip() else {
        bail!("VLESS UDP test request only constructs IPv4 targets");
    };
    request.extend_from_slice(&ipv4.octets());
    request.put_u16(payload.len() as u16);
    request.extend_from_slice(payload);
    Ok(request.freeze())
}

/// Wraps a single UDP datagram in the 2-byte length prefix VLESS uses
/// inside the WebSocket frame stream.
fn vless_udp_datagram(payload: &[u8]) -> Bytes {
    let mut frame = BytesMut::with_capacity(2 + payload.len());
    frame.put_u16(payload.len() as u16);
    frame.extend_from_slice(payload);
    frame.freeze()
}

/// Builds the VLESS handshake bytes for the MUX command. Per mux.cool
/// the request target is the literal `v1.mux.cool` with port 0 — real
/// sub-connection targets ride inside the mux frames that follow.
fn vless_mux_request(uuid: &str) -> Result<Bytes> {
    let mut request = Vec::with_capacity(48);
    request.push(VLESS_VERSION);
    request.extend_from_slice(&parse_uuid(uuid)?);
    request.push(0);
    request.push(COMMAND_MUX);
    request.extend_from_slice(&0_u16.to_be_bytes()); // port = 0
    request.push(0x02); // atype: domain
    let domain = b"v1.mux.cool";
    request.push(domain.len() as u8);
    request.extend_from_slice(domain);
    Ok(Bytes::from(request))
}

/// Builds a mux New frame for `session_id` targeting `target` with an
/// initial TCP payload. Used by the mux resumption test to open
/// sub-connections inside an established VLESS-mux session.
fn vless_mux_new_tcp_frame(session_id: u16, target: SocketAddr, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    let target_addr = TargetAddr::Socket(target);
    encode_frame(
        &mut buf,
        session_id,
        SessionStatus::New,
        OPTION_DATA,
        Some(MuxNetwork::Tcp),
        Some(&target_addr),
        Some(payload),
    );
    buf.freeze()
}

/// Builds a mux Keep frame carrying additional payload on an existing
/// sub-connection. The target field is omitted because the
/// sub-connection's destination was already pinned at New time.
fn vless_mux_keep_frame(session_id: u16, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    encode_frame(
        &mut buf,
        session_id,
        SessionStatus::Keep,
        OPTION_DATA,
        None,
        None,
        Some(payload),
    );
    buf.freeze()
}

/// Reads mux frames off the WebSocket until it has captured one
/// inbound frame for each requested `expected_session` ID. Returns a
/// map from session_id to the frame's data payload.
///
/// The caller must specify exactly which session IDs to wait for —
/// the test treats arrival order as undefined because two upstream
/// echoes race on independent TCP sockets.
async fn collect_mux_keep_payloads<S>(
    socket: &mut S,
    expected: &[u16],
) -> Result<std::collections::HashMap<u16, Vec<u8>>>
where
    S: futures_util::Stream<
            Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    let mut payloads: std::collections::HashMap<u16, Vec<u8>> =
        std::collections::HashMap::new();
    while !expected.iter().all(|id| payloads.contains_key(id)) {
        let bytes = expect_binary_reply(socket).await?;
        let ParsedFrame { meta, data, consumed } = parse_frame(&bytes)?
            .ok_or_else(|| anyhow::anyhow!("incomplete mux frame in WS message"))?;
        if consumed != bytes.len() {
            // The server's encode_frame writes one frame per ws-binary
            // message in this codepath; if that ever stops being true
            // the test will flag it loudly.
            bail!(
                "expected exactly one mux frame per WS binary message, got {consumed} of {} bytes",
                bytes.len()
            );
        }
        if meta.status == SessionStatus::Keep
            && let Some(payload) = data
            && expected.contains(&meta.session_id)
            && !payloads.contains_key(&meta.session_id)
        {
            payloads.insert(meta.session_id, payload.to_vec());
        }
    }
    Ok(payloads)
}

// ── Raw-QUIC helpers (only used by the raw-QUIC test below) ──────────────────

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sockudo_ws::{
    Config as H3WsConfig, Http3 as H3Transport, WebSocketServer as H3WebSocketServer,
};

use super::super::serve_h3_server;
use crate::config::H3Alpn;

fn raw_quic_test_tls() -> Result<(rustls::ServerConfig, CertificateDer<'static>)> {
    super::super::ensure_rustls_provider_installed();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)?;
    tls_config.alpn_protocols = vec![b"vless".to_vec()];
    Ok((tls_config, cert_der))
}

async fn bind_raw_quic_test_server(
    addr: SocketAddr,
    tls_config: rustls::ServerConfig,
) -> Result<H3WebSocketServer<H3Transport>> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|_| anyhow::anyhow!("invalid raw-quic test TLS config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let mut transport = quinn::TransportConfig::default();
    transport
        .datagram_receive_buffer_size(Some(1 << 20))
        .datagram_send_buffer_size(1 << 20);
    server_config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    Ok(H3WebSocketServer::<H3Transport>::from_endpoint(
        endpoint,
        H3WsConfig::default(),
    ))
}

fn raw_quic_client_config(cert_der: CertificateDer<'static>) -> Result<quinn::ClientConfig> {
    super::super::ensure_rustls_provider_installed();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der)?;
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"vless".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

/// Builds a VLESS TCP request whose Addons section carries a single
/// resumption opcode pair: `RESUME_CAPABLE=0x01` and (optionally)
/// `RESUME_ID=<bytes>`. Returns the raw bytes ready to be written
/// into a QUIC bidi stream.
fn vless_raw_quic_tcp_request_with_resume(
    uuid: &str,
    target: SocketAddr,
    payload: &[u8],
    requested_resume: Option<&SessionId>,
) -> Result<Bytes> {
    let mut addons = Vec::new();
    addons.push(ADDON_TAG_RESUME_CAPABLE);
    addons.push(1);
    addons.push(0x01);
    if let Some(id) = requested_resume {
        addons.push(ADDON_TAG_RESUME_ID);
        addons.push(16);
        addons.extend_from_slice(id.as_bytes());
    }
    if addons.len() > u8::MAX as usize {
        bail!("test addons block too large: {} bytes", addons.len());
    }

    let mut request = Vec::new();
    request.push(VLESS_VERSION);
    request.extend_from_slice(&parse_uuid(uuid)?);
    request.push(addons.len() as u8);
    request.extend_from_slice(&addons);
    request.push(COMMAND_TCP);
    request.extend_from_slice(&target.port().to_be_bytes());
    request.push(0x01); // IPv4
    let std::net::IpAddr::V4(ipv4) = target.ip() else {
        bail!("raw-quic test target must be IPv4");
    };
    request.extend_from_slice(&ipv4.octets());
    request.extend_from_slice(payload);
    Ok(Bytes::from(request))
}

#[derive(Debug, Default)]
struct ParsedVlessResponse {
    session_id: Option<SessionId>,
    resume_result: Option<u8>,
}

/// Parses the VLESS raw-QUIC TCP response header out of a slice. The
/// wire shape is `[VERSION, addons_len, addons...]`. `addons_len` may
/// be `0` for legacy clients; this test always negotiates resumption,
/// so we expect non-zero on every successful handshake.
fn parse_vless_raw_quic_tcp_response(buf: &[u8]) -> Result<(ParsedVlessResponse, usize)> {
    if buf.len() < 2 {
        bail!("response truncated: only {} bytes", buf.len());
    }
    if buf[0] != VLESS_VERSION {
        bail!("unexpected VLESS response version: {:#x}", buf[0]);
    }
    let addons_len = buf[1] as usize;
    let addons_start = 2;
    let addons_end = addons_start + addons_len;
    if buf.len() < addons_end {
        bail!(
            "response truncated: declared {} addon bytes but only {} available",
            addons_len,
            buf.len() - addons_start
        );
    }
    let mut response = ParsedVlessResponse::default();
    let block = &buf[addons_start..addons_end];
    let mut i = 0;
    while i + 2 <= block.len() {
        let tag = block[i];
        let len = block[i + 1] as usize;
        let value_start = i + 2;
        let value_end = value_start + len;
        if value_end > block.len() {
            break;
        }
        let value = &block[value_start..value_end];
        match tag {
            ADDON_TAG_SESSION_ID => {
                if let Ok(arr) = <[u8; 16]>::try_from(value) {
                    response.session_id = Some(SessionId::from_bytes(arr));
                }
            },
            ADDON_TAG_RESUME_RESULT => {
                if value.len() == 1 {
                    response.resume_result = Some(value[0]);
                }
            },
            _ => {},
        }
        i = value_end;
    }
    Ok((response, addons_end))
}

/// Stand-up of a raw-QUIC VLESS server with `[session_resumption]`
/// enabled. Returns the listen address, the lone `VlessUser`, the
/// CA cert needed by the client, and a JoinHandle that aborts the
/// background `serve_h3_server` task on drop.
async fn spawn_raw_quic_vless_resumption_server() -> Result<(
    SocketAddr,
    VlessUser,
    CertificateDer<'static>,
    JoinHandle<Result<()>>,
)> {
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let (tls_config, cert_der) = raw_quic_test_tls()?;
    let server = bind_raw_quic_test_server(server_addr, tls_config).await?;
    let listen_addr = server.local_addr()?;

    let dummy_listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = sample_config(dummy_listen);
    config.session_resumption.enabled = true;

    let metrics = Metrics::new(&config);
    let orphan_registry = Arc::new(OrphanRegistry::new(
        ResumptionConfig::from(&config.session_resumption),
        Arc::clone(&metrics),
    ));

    let vless_user = VlessUser::new("550e8400-e29b-41d4-a716-446655440000".into(), None)?;
    let raw_vless_users: Arc<[VlessUser]> = Arc::from(vec![vless_user.clone()].into_boxed_slice());
    let raw_vless_candidates: Arc<[Arc<str>]> =
        Arc::from(vec![vless_user.label_arc()].into_boxed_slice());

    let routes = Arc::new(ArcSwap::from_pointee(RouteRegistry {
        tcp: Arc::new(std::collections::BTreeMap::new()),
        udp: Arc::new(std::collections::BTreeMap::new()),
        vless: Arc::new(std::collections::BTreeMap::new()),
    }));
    let services = Arc::new(Services::new(
        Arc::clone(&metrics),
        DnsCache::new(Duration::from_secs(30)),
        false,
        None,
        UdpServices {
            nat_table: super::super::nat::NatTable::new(Duration::from_secs(300)),
            replay_store: super::super::replay::ReplayStore::new(Duration::from_secs(300), 0),
            relay_semaphore: None,
        },
        Some(orphan_registry),
    ));
    let auth = Arc::new(AuthPolicy {
        users: Arc::new(ArcSwap::from_pointee(UserKeySlice(Arc::from(
            Vec::<UserKey>::new().into_boxed_slice(),
        )))),
        http_root_auth: false,
        http_root_realm: Arc::from("Authorization required"),
    });

    let task = tokio::spawn(async move {
        serve_h3_server(
            server,
            routes,
            services,
            auth,
            Arc::from(vec![H3Alpn::Vless].into_boxed_slice()),
            raw_vless_users,
            raw_vless_candidates,
            Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
            ShutdownSignal::never(),
        )
        .await
    });

    Ok((listen_addr, vless_user, cert_der, task))
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
async fn vless_raw_quic_resume_hit_skips_fresh_upstream() -> Result<()> {
    // Park a VLESS-TCP-over-raw-QUIC session, then resume it through
    // a fresh raw-QUIC connection. The mock TCP echo target's accept
    // counter must stay at 1 across both QUIC sessions — proof that
    // `try_park_raw_quic_tcp` and `try_attach_parked_tcp` line up.
    let (target_addr, target_accepts) = spawn_echo_target().await?;
    let (listen_addr, vless_user, cert_der, server_task) =
        spawn_raw_quic_vless_resumption_server().await?;
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let _ = vless_user; // silence unused: identity is encoded in the request UUID

    // ── Session #1: fresh raw-QUIC dial with `RESUME_CAPABLE` ─────────
    let mut endpoint_1 =
        quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint_1.set_default_client_config(raw_quic_client_config(cert_der.clone())?);
    let connection_1 = endpoint_1.connect(listen_addr, "localhost")?.await?;
    let (mut send_1, mut recv_1) = connection_1.open_bi().await?;

    let request = vless_raw_quic_tcp_request_with_resume(uuid, target_addr, b"ping1", None)?;
    send_1.write_all(&request).await?;

    // Read enough bytes for the response header. Addons block carrying
    // SESSION_ID (16 + 2) plus the leading two-byte preamble = 20 bytes
    // is the upper bound for the resume-capable handshake.
    let mut header_buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), recv_1.read(&mut header_buf))
        .await?
        .map_err(|e| anyhow::anyhow!("read VLESS response on first session: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("VLESS response: stream closed before header"))?;
    let (response, header_len) = parse_vless_raw_quic_tcp_response(&header_buf[..n])?;
    let session_id = response
        .session_id
        .ok_or_else(|| anyhow::anyhow!("server didn't issue SESSION_ID despite RESUME_CAPABLE"))?;
    assert!(
        response.resume_result.is_none(),
        "fresh handshake should not carry RESUME_RESULT"
    );

    // The same chunk may already carry the echoed payload after the
    // header. If not, read more.
    let mut echoed = Vec::new();
    if header_len < n {
        echoed.extend_from_slice(&header_buf[header_len..n]);
    }
    while echoed.len() < 5 {
        let mut more = [0u8; 64];
        let read = recv_1
            .read(&mut more)
            .await
            .map_err(|e| anyhow::anyhow!("read echoed payload: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("echo: stream closed early"))?;
        echoed.extend_from_slice(&more[..read]);
    }
    assert_eq!(&echoed[..5], b"ping1");
    assert_eq!(target_accepts.load(Ordering::SeqCst), 1);

    // Close the QUIC stream gracefully. `send.finish()` flushes a
    // FIN; once the server-side upload task observes `recv == None`
    // it fires the cancel notify so the download task hands its
    // reader back for parking. We must give the server enough time
    // to run that whole sequence *before* tearing the QUIC connection
    // down — otherwise the connection abort wins the race and the
    // park-on-drop path is skipped (download returns `Drained` on a
    // ResetStream error).
    let _ = send_1.finish();
    drop(recv_1);
    drop(send_1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(connection_1);
    endpoint_1.close(0u32.into(), b"resume");
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── Session #2: fresh raw-QUIC dial with `RESUME_ID` ──────────────
    let mut endpoint_2 =
        quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint_2.set_default_client_config(raw_quic_client_config(cert_der)?);
    let connection_2 = endpoint_2.connect(listen_addr, "localhost")?.await?;
    let (mut send_2, mut recv_2) = connection_2.open_bi().await?;

    let request =
        vless_raw_quic_tcp_request_with_resume(uuid, target_addr, b"ping2", Some(&session_id))?;
    send_2.write_all(&request).await?;

    let mut header_buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), recv_2.read(&mut header_buf))
        .await?
        .map_err(|e| anyhow::anyhow!("read VLESS response on resumed session: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("VLESS resume response: stream closed early"))?;
    let (response, header_len) = parse_vless_raw_quic_tcp_response(&header_buf[..n])?;
    assert_eq!(
        response.resume_result, Some(0x00),
        "expected RESUME_RESULT=Hit (0x00) in raw-QUIC resume response"
    );
    assert!(
        response.session_id.is_some(),
        "resume hit must still echo a SESSION_ID"
    );

    let mut echoed = Vec::new();
    if header_len < n {
        echoed.extend_from_slice(&header_buf[header_len..n]);
    }
    while echoed.len() < 5 {
        let mut more = [0u8; 64];
        let read = recv_2
            .read(&mut more)
            .await
            .map_err(|e| anyhow::anyhow!("read echoed payload (resumed): {e}"))?
            .ok_or_else(|| anyhow::anyhow!("echo on resumed session: stream closed early"))?;
        echoed.extend_from_slice(&more[..read]);
    }
    assert_eq!(&echoed[..5], b"ping2");
    assert_eq!(
        target_accepts.load(Ordering::SeqCst),
        1,
        "resume hit must reuse parked raw-QUIC TCP upstream"
    );

    let _ = send_2.finish();
    drop(connection_2);
    endpoint_2.close(0u32.into(), b"done");
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test]
async fn ss_udp_resume_across_h1_to_h2_transport_switch() -> Result<()> {
    // Cross-transport variant of `ss_udp_resume_hit_reattaches_parked_nat_entry`:
    // park the SS-UDP NAT entry on an HTTP/1 stream, then resume it
    // through an HTTP/2 (RFC 8441) Extended CONNECT stream. The
    // upstream NAT entry must be re-pointed at the H2 sender — no
    // fresh ephemeral port allocation.
    //
    // This is the original motivating scenario for the whole feature
    // (intermittent UDP path between two VMs forces clients to drop
    // QUIC / H3 and fall back to TCP-based H2 transport while the
    // session continues).
    let (target_addr, sources) = spawn_echo_udp_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // Session #1 over HTTP/1.
    let (mut h1_socket, h1_issued) = connect_ws_h1(server.listen_addr, "/udp", None, true).await?;
    let session_id = h1_issued
        .ok_or_else(|| anyhow::anyhow!("HTTP/1 SS-UDP server didn't mint Session ID"))?;
    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"udp-h1");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    h1_socket.send(WsMessage::Binary(ciphertext.into())).await?;
    let _ = expect_binary_reply(&mut h1_socket).await?;
    assert_eq!(sources.lock().await.len(), 1);

    h1_socket.close(None).await?;
    drop(h1_socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2 over HTTP/2 on the same /udp path.
    let (mut h2_socket, h2_outcome) =
        connect_ws_h2(server.listen_addr, "/udp", Some(session_id), true).await?;
    assert!(
        h2_outcome.issued_session_id.is_some(),
        "H2 SS-UDP reply must still echo a Session ID even on resume"
    );

    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"udp-h2");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    h2_socket.send(WsMessage::Binary(ciphertext.into())).await?;
    let _ = expect_binary_reply(&mut h2_socket).await?;

    assert_eq!(
        sources.lock().await.len(),
        1,
        "ss-udp resume across H1→H2 must reuse the parked NAT entry — fresh source port indicates miss"
    );

    h2_socket.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn ss_udp_resume_hit_reattaches_parked_nat_entry() -> Result<()> {
    // SS UDP through WebSocket: each client packet is an independent
    // SS-AEAD-encrypted datagram carrying its own target inline. The
    // server lazy-creates one NAT entry per `(user, fwmark, target)`
    // and registers this WS stream as the active outbound responder.
    // On resume, every NAT key the parked stream owned is re-pointed
    // at the new sender — without re-binding any upstream socket.
    //
    // The probe is the upstream socket's view of unique source
    // addresses: one parked NAT entry stays at cardinality 1 across
    // the reconnect, while a missed resume would cause the server to
    // bind a fresh ephemeral socket on the second packet (cardinality
    // 2).
    let (target_addr, sources) = spawn_echo_udp_target().await?;
    let (server, user) = spawn_ss_resumption_server(|_| {}).await?;

    // ── Session #1: dial /udp, push one encrypted datagram, expect
    //               an encrypted reply back. ──────────────────────
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/udp", None, true).await?;
    let session_id = issued
        .ok_or_else(|| anyhow::anyhow!("ss-udp server didn't mint Session ID"))?;

    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"udp1");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    socket.send(WsMessage::Binary(ciphertext.into())).await?;

    let _reply = expect_binary_reply(&mut socket).await?;
    assert_eq!(sources.lock().await.len(), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ── Session #2: resume. Server's `attempt_ss_udp_resume` must
    //               re-point the parked NAT entry at the new
    //               outbound channel before this packet is sent
    //               upstream — so the source port stays the same. ──
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/udp", Some(session_id), true).await?;
    let mut plaintext = TargetAddr::Socket(target_addr).encode()?;
    plaintext.extend_from_slice(b"udp2");
    let ciphertext = encrypt_udp_packet(&user, &plaintext)?;
    socket2.send(WsMessage::Binary(ciphertext.into())).await?;
    let _reply = expect_binary_reply(&mut socket2).await?;

    assert_eq!(
        sources.lock().await.len(),
        1,
        "ss-udp resume must reuse the parked NAT entry — exactly one upstream source observed"
    );

    socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn vless_udp_single_resume_hit_reuses_parked_socket() -> Result<()> {
    let (target_addr, sources) = spawn_echo_udp_target().await?;
    let (server, _user) = spawn_vless_resumption_server().await?;
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    // Session #1: open VLESS-UDP, send a datagram, expect the standard
    // `[VERSION, 0x00]` response header followed by the echoed
    // length-prefixed payload.
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/vless", None, true).await?;
    let session_id =
        issued.ok_or_else(|| anyhow::anyhow!("VLESS UDP server didn't mint Session ID"))?;
    socket
        .send(WsMessage::Binary(vless_udp_request(uuid, target_addr, b"udp1")?))
        .await?;
    let header = expect_binary_reply(&mut socket).await?;
    assert_eq!(header.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoed = expect_binary_reply(&mut socket).await?;
    // Server frames upstream packets the same way: `len:u16 + bytes`.
    assert_eq!(echoed.len(), 2 + 4);
    assert_eq!(&echoed[2..], b"udp1");
    assert_eq!(sources.lock().await.len(), 1);
    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Session #2: resume. Server re-attaches the parked `UdpSocket`
    // and sends another `[VERSION, 0x00]` so the client parser still
    // sees a clean handshake response. Then we push another datagram
    // through the resumed socket — the echo should arrive from the
    // *same* source port the parked socket was bound to.
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/vless", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(vless_udp_request(uuid, target_addr, b"udp2")?))
        .await?;
    let header2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(header2.as_ref(), &[VLESS_VERSION, 0x00]);
    let echoed2 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(&echoed2[2..], b"udp2");

    // Final assertion: the echo target saw datagrams from exactly one
    // source `SocketAddr` across both sessions — the parked socket
    // was the one used on resume, not a freshly bound replacement.
    assert_eq!(
        sources.lock().await.len(),
        1,
        "vless udp resume must reuse the parked upstream socket (one source port observed)"
    );

    // For good measure send a third datagram via Keep-style
    // length-prefixed framing (no VLESS handshake on already-open
    // session) — and verify the source still doesn't multiply.
    socket2
        .send(WsMessage::Binary(vless_udp_datagram(b"udp3")))
        .await?;
    let echoed3 = expect_binary_reply(&mut socket2).await?;
    assert_eq!(&echoed3[2..], b"udp3");
    assert_eq!(sources.lock().await.len(), 1);

    socket2.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn vless_mux_resume_hit_preserves_all_sub_conns() -> Result<()> {
    // Two independent TCP echo targets behind two separate mux
    // sub-connections. After park + resume both sub-conns must still
    // route to their original upstream — neither target's accept
    // counter should grow on the second WS session.
    let (target_a, accepts_a) = spawn_echo_target().await?;
    let (target_b, accepts_b) = spawn_echo_target().await?;
    let (server, _user) = spawn_vless_resumption_server().await?;
    let uuid = "550e8400-e29b-41d4-a716-446655440000";

    // ── Session #1: open mux with sub-conns 1 and 2 ────────────────
    let (mut socket, issued) = connect_ws_h1(server.listen_addr, "/vless", None, true).await?;
    let session_id = issued
        .ok_or_else(|| anyhow::anyhow!("VLESS mux server didn't mint Session ID"))?;

    // Combine the VLESS mux handshake with two mux New frames in a
    // single WS binary message, matching the smoke test's pattern.
    let mut handshake = BytesMut::from(vless_mux_request(uuid)?.as_ref());
    handshake.extend_from_slice(&vless_mux_new_tcp_frame(1, target_a, b"a-ping1"));
    handshake.extend_from_slice(&vless_mux_new_tcp_frame(2, target_b, b"b-ping1"));
    socket.send(WsMessage::Binary(handshake.freeze())).await?;

    // First binary reply is the VLESS handshake response.
    let response_header = expect_binary_reply(&mut socket).await?;
    assert_eq!(response_header.as_ref(), &[VLESS_VERSION, 0x00]);

    // Each upstream echoes its payload back — collect by session ID
    // (order is undefined since sub-conns race independently).
    let echoes = collect_mux_keep_payloads(&mut socket, &[1, 2]).await?;
    assert_eq!(echoes[&1], b"a-ping1");
    assert_eq!(echoes[&2], b"b-ping1");
    assert_eq!(accepts_a.load(Ordering::SeqCst), 1);
    assert_eq!(accepts_b.load(Ordering::SeqCst), 1);

    socket.close(None).await?;
    drop(socket);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ── Session #2: resume the mux atomically. Both sub-conns must
    //               still be routed to their original targets. ────
    let (mut socket2, _) =
        connect_ws_h1(server.listen_addr, "/vless", Some(session_id), true).await?;
    socket2
        .send(WsMessage::Binary(vless_mux_request(uuid)?))
        .await?;
    let response_header = expect_binary_reply(&mut socket2).await?;
    assert_eq!(response_header.as_ref(), &[VLESS_VERSION, 0x00]);

    // Probe the resumed sub-conns with fresh Keep payloads. The
    // server should forward each into the parked upstream, and the
    // upstream should echo it straight back.
    socket2
        .send(WsMessage::Binary(vless_mux_keep_frame(1, b"a-ping2")))
        .await?;
    socket2
        .send(WsMessage::Binary(vless_mux_keep_frame(2, b"b-ping2")))
        .await?;
    let echoes = collect_mux_keep_payloads(&mut socket2, &[1, 2]).await?;
    assert_eq!(echoes[&1], b"a-ping2");
    assert_eq!(echoes[&2], b"b-ping2");

    // Critical assertion: no fresh upstream connects on resume.
    assert_eq!(
        accepts_a.load(Ordering::SeqCst),
        1,
        "mux resume must reuse parked TCP sub-conn for target A"
    );
    assert_eq!(
        accepts_b.load(Ordering::SeqCst),
        1,
        "mux resume must reuse parked TCP sub-conn for target B"
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

