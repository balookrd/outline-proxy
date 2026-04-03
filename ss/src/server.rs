use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use bytes::Bytes;

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::{
        OriginalUri, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Method, StatusCode, Version},
    response::IntoResponse,
    routing::any,
    serve::ListenerExt,
};
use futures_util::{FutureExt, SinkExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sockudo_ws::{
    Config as H3WebSocketConfig, ExtendedConnectRequest as H3ExtendedConnectRequest,
    Http3 as H3Transport, Message as H3Message, Stream as H3Stream,
    WebSocketServer as H3WebSocketServer, WebSocketStream as H3WebSocketStream,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::mpsc,
    task::JoinSet,
    time::{Duration, timeout},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE, UserKey,
        decrypt_udp_packet, decrypt_udp_packet_with_hint, diagnose_stream_handshake,
        diagnose_udp_packet,
    },
    fwmark::apply_fwmark_if_needed,
    metrics::{DisconnectReason, Metrics, Protocol, TcpUpstreamGuard, Transport},
    nat::{NatKey, NatTable, UdpResponseSender},
    protocol::{TargetAddr, parse_target_addr},
};

const H2_KEEPALIVE_INTERVAL_SECS: u64 = 20;
const H2_KEEPALIVE_TIMEOUT_SECS: u64 = 20;
const H2_STREAM_WINDOW_BYTES: u32 = 16 * 1024 * 1024; // 16 MB
const H2_CONNECTION_WINDOW_BYTES: u32 = 64 * 1024 * 1024; // 64 MB
const H2_MAX_SEND_BUF_SIZE: usize = 16 * 1024 * 1024; // 16 MB
const H3_QUIC_IDLE_TIMEOUT_SECS: u64 = 120;
const H3_QUIC_PING_INTERVAL_SECS: u64 = 10;
// Flow control windows: larger values allow higher throughput at high RTT.
// Stream window must be <= connection window.
const H3_STREAM_WINDOW_BYTES: u64 = 16 * 1024 * 1024; // 16 MB (was 8 MB)
const H3_CONNECTION_WINDOW_BYTES: u64 = 64 * 1024 * 1024; // 64 MB (was 32 MB)
const H3_MAX_CONCURRENT_BIDI_STREAMS: u32 = 4_096;
const H3_MAX_CONCURRENT_UNI_STREAMS: u32 = 1_024;
// Larger write buffer reduces per-packet overhead by batching more data per send.
const H3_WRITE_BUFFER_BYTES: usize = 512 * 1024; // 512 KB (was 256 KB)
// Higher backpressure threshold avoids dropping connections for transiently slow clients.
const H3_MAX_BACKPRESSURE_BYTES: usize = 16 * 1024 * 1024; // 16 MB (was 8 MB)
// Larger OS UDP socket buffers are the primary defense against packet drops under burst load.
// Increase net.core.rmem_max / kern.ipc.maxsockbuf on the host if the OS silently caps this.
const H3_UDP_SOCKET_BUFFER_BYTES: usize = 32 * 1024 * 1024; // 32 MB (was 8 MB)
const H3_MAX_UDP_PAYLOAD_SIZE: u16 = 1_350;
const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;
const TCP_HAPPY_EYEBALLS_DELAY_MS: u64 = 250;
const UDP_MAX_CONCURRENT_RELAY_TASKS: usize = 256;
const UDP_DNS_CACHE_TTL_SECS: u64 = 30;
const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;
const UDP_CACHED_USER_INDEX_EMPTY: usize = usize::MAX;

#[derive(Clone)]
struct AppState {
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
}

#[derive(Clone)]
struct TransportRoute {
    users: Arc<[UserKey]>,
    candidate_users: Arc<[String]>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct UdpDnsCacheKey {
    host: String,
    port: u16,
    prefer_ipv4_upstream: bool,
}

#[derive(Clone, Copy, Debug)]
struct UdpDnsCacheEntry {
    resolved: SocketAddr,
    expires_at: std::time::Instant,
}

struct UdpDnsCache {
    entries: RwLock<HashMap<UdpDnsCacheKey, UdpDnsCacheEntry>>,
    ttl: Duration,
}

impl UdpDnsCache {
    fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
        })
    }

    fn lookup(&self, host: &str, port: u16, prefer_ipv4_upstream: bool) -> Option<SocketAddr> {
        let key = UdpDnsCacheKey {
            host: host.to_owned(),
            port,
            prefer_ipv4_upstream,
        };
        let now = std::time::Instant::now();
        if let Some(entry) = self
            .entries
            .read()
            .expect("udp dns cache poisoned")
            .get(&key)
            .copied()
        {
            if entry.expires_at > now {
                return Some(entry.resolved);
            }
        }

        let mut entries = self.entries.write().expect("udp dns cache poisoned");
        if let Some(entry) = entries.get(&key).copied() {
            if entry.expires_at > now {
                return Some(entry.resolved);
            }
            entries.remove(&key);
        }
        None
    }

    fn store(&self, host: &str, port: u16, prefer_ipv4_upstream: bool, resolved: SocketAddr) {
        let key = UdpDnsCacheKey {
            host: host.to_owned(),
            port,
            prefer_ipv4_upstream,
        };
        let entry = UdpDnsCacheEntry {
            resolved,
            expires_at: std::time::Instant::now() + self.ttl,
        };
        self.entries
            .write()
            .expect("udp dns cache poisoned")
            .insert(key, entry);
    }
}

pub async fn run(config: Config) -> Result<()> {
    ensure_rustls_provider_installed();
    let config = Arc::new(config);
    let metrics = Metrics::new(config.as_ref());
    metrics.start_process_memory_sampler();
    let users = build_users(&config)?;
    let tcp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp));
    let udp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp));
    let nat_table = NatTable::new(Duration::from_secs(config.udp_nat_idle_timeout_secs));
    let udp_dns_cache = UdpDnsCache::new(Duration::from_secs(UDP_DNS_CACHE_TTL_SECS));
    let app = build_app(
        tcp_routes.clone(),
        udp_routes.clone(),
        metrics.clone(),
        Arc::clone(&nat_table),
        Arc::clone(&udp_dns_cache),
        config.prefer_ipv4_upstream,
    );
    let listener = if let Some(listen) = config.listen {
        Some(
            TcpListener::bind(listen)
                .await
                .with_context(|| format!("failed to bind {}", listen))?,
        )
    } else {
        None
    };
    let ss_tcp_listener =
        if let Some(ss_listen) = config.ss_listen {
            Some(TcpListener::bind(ss_listen).await.with_context(|| {
                format!("failed to bind shadowsocks tcp listener {}", ss_listen)
            })?)
        } else {
            None
        };
    let ss_udp_socket = if let Some(ss_listen) = config.ss_listen {
        Some(Arc::new(UdpSocket::bind(ss_listen).await.with_context(
            || format!("failed to bind shadowsocks udp socket {}", ss_listen),
        )?))
    } else {
        None
    };
    let metrics_listener = if config.metrics_enabled() {
        let metrics_listen = config.metrics_listen.expect("metrics listen must exist");
        Some(
            TcpListener::bind(metrics_listen)
                .await
                .with_context(|| format!("failed to bind metrics listener {}", metrics_listen))?,
        )
    } else {
        None
    };
    let h3_server = if config.h3_enabled() {
        Some(build_h3_server(config.as_ref()).await?)
    } else {
        None
    };

    // Periodic NAT entry eviction.
    {
        let nat_table_cleanup = Arc::clone(&nat_table);
        let metrics_cleanup = Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                nat_table_cleanup.evict_idle(&metrics_cleanup).await;
            }
        });
    }

    let tcp_paths = tcp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let udp_paths = udp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let user_routes = describe_user_routes(users.as_ref());
    info!(
        listen = ?config.listen,
        ss_listen = ?config.ss_listen,
        tcp_tls = config.tcp_tls_enabled(),
        h3_listen = ?config.effective_h3_listen(),
        metrics_listen = ?config.metrics_listen,
        metrics_path = %config.metrics_path,
        default_tcp_ws_path = %config.ws_path_tcp,
        default_udp_ws_path = %config.ws_path_udp,
        tcp_ws_paths = ?tcp_paths,
        udp_ws_paths = ?udp_paths,
        user_routes = ?user_routes,
        method = ?config.method,
        users = users.len(),
        udp_nat_idle_timeout_secs = config.udp_nat_idle_timeout_secs,
        prefer_ipv4_upstream = config.prefer_ipv4_upstream,
        "websocket shadowsocks server listening",
    );

    let mut tasks = JoinSet::new();
    if let Some(listener) = listener {
        let config = Arc::clone(&config);
        tasks.spawn(async move { serve_tcp_listener(listener, app, config).await });
    }
    if let Some(h3_server) = h3_server {
        let tcp_routes = tcp_routes.clone();
        let udp_routes = udp_routes.clone();
        let metrics = metrics.clone();
        let nat_table = Arc::clone(&nat_table);
        let udp_dns_cache = Arc::clone(&udp_dns_cache);
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        tasks.spawn(async move {
            serve_h3_server(
                h3_server,
                tcp_routes,
                udp_routes,
                metrics,
                nat_table,
                udp_dns_cache,
                prefer_ipv4_upstream,
            )
            .await
        });
    }
    if let Some(metrics_listener) = metrics_listener {
        let metrics_app = build_metrics_app(metrics.clone(), config.metrics_path.clone());
        tasks.spawn(async move { serve_metrics_listener(metrics_listener, metrics_app).await });
    }
    if let Some(listener) = ss_tcp_listener {
        let users = users.clone();
        let metrics = metrics.clone();
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        tasks.spawn(async move {
            serve_ss_tcp_listener(listener, users, metrics, prefer_ipv4_upstream).await
        });
    }
    if let Some(socket) = ss_udp_socket {
        let users = users.clone();
        let metrics = metrics.clone();
        let nat_table = Arc::clone(&nat_table);
        let udp_dns_cache = Arc::clone(&udp_dns_cache);
        let prefer_ipv4_upstream = config.prefer_ipv4_upstream;
        tasks.spawn(async move {
            serve_ss_udp_socket(
                socket,
                users,
                metrics,
                nat_table,
                udp_dns_cache,
                prefer_ipv4_upstream,
            )
            .await
        });
    }

    while let Some(result) = tasks.join_next().await {
        result.context("server task join failed")??;
    }
    Ok(())
}

async fn tcp_websocket_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
) -> axum::response::Response {
    let protocol = protocol_from_http_version(version);
    let path = uri.path().to_owned();
    let route = state
        .tcp_routes
        .get(&path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
    let session = state
        .metrics
        .open_websocket_session(Transport::Tcp, protocol);
    ws.on_upgrade(move |socket| async move {
        let outcome = match handle_tcp_connection(
            socket,
            route.users,
            state.metrics.clone(),
            protocol,
            path.clone(),
            route.candidate_users,
            state.prefer_ipv4_upstream,
        )
        .await
        {
            Ok(()) => DisconnectReason::Normal,
            Err(error) => {
                if is_normal_h3_shutdown(&error) {
                    debug!(?error, "tcp websocket connection closed normally");
                    DisconnectReason::Normal
                } else if is_benign_ws_disconnect(&error) {
                    debug!(?error, "tcp websocket connection closed abruptly");
                    DisconnectReason::ClientDisconnect
                } else {
                    warn!(?error, "tcp websocket connection terminated with error");
                    DisconnectReason::Error
                }
            }
        };
        session.finish(outcome);
    })
}

async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics.render_prometheus(),
    )
}

async fn udp_websocket_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
) -> axum::response::Response {
    // UDP over WebSocket is latency-sensitive, so avoid tungstenite-side batching.
    let ws = ws.write_buffer_size(0);
    let protocol = protocol_from_http_version(version);
    let path = uri.path().to_owned();
    let route = state
        .udp_routes
        .get(&path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
    let session = state
        .metrics
        .open_websocket_session(Transport::Udp, protocol);
    let nat_table = state.nat_table.clone();
    ws.on_upgrade(move |socket| async move {
        let outcome = match handle_udp_connection(
            socket,
            route.users,
            state.metrics.clone(),
            protocol,
            path.clone(),
            route.candidate_users,
            nat_table,
            state.udp_dns_cache.clone(),
            state.prefer_ipv4_upstream,
        )
        .await
        {
            Ok(()) => DisconnectReason::Normal,
            Err(error) => {
                if is_normal_h3_shutdown(&error) {
                    debug!(?error, "udp websocket connection closed normally");
                    DisconnectReason::Normal
                } else if is_benign_ws_disconnect(&error) {
                    debug!(?error, "udp websocket connection closed abruptly");
                    DisconnectReason::ClientDisconnect
                } else {
                    warn!(?error, "udp websocket connection terminated with error");
                    DisconnectReason::Error
                }
            }
        };
        session.finish(outcome);
    })
}

fn protocol_from_http_version(version: Version) -> Protocol {
    match version {
        Version::HTTP_2 => Protocol::Http2,
        _ => Protocol::Http1,
    }
}

struct TcpRelayState {
    upstream_writer: Option<tokio::net::tcp::OwnedWriteHalf>,
    upstream_to_client: Option<tokio::task::JoinHandle<Result<()>>>,
    authenticated_user: Option<UserKey>,
    upstream_guard: Option<TcpUpstreamGuard>,
}

impl TcpRelayState {
    fn new() -> Self {
        Self {
            upstream_writer: None,
            upstream_to_client: None,
            authenticated_user: None,
            upstream_guard: None,
        }
    }
}

fn ws_binary_message(data: Bytes) -> Message {
    Message::Binary(data)
}

fn ws_pong_message(payload: Bytes) -> Message {
    Message::Pong(payload)
}

fn ws_close_message() -> Message {
    Message::Close(None)
}

fn h3_binary_message(data: Bytes) -> H3Message {
    H3Message::Binary(data)
}

fn h3_pong_message(payload: Bytes) -> H3Message {
    H3Message::Pong(payload)
}

fn h3_close_message() -> H3Message {
    H3Message::Close(None)
}

fn make_ws_udp_response_sender(tx: mpsc::Sender<Message>, protocol: Protocol) -> UdpResponseSender {
    UdpResponseSender::ws(tx, protocol)
}

fn make_h3_udp_response_sender(
    tx: mpsc::Sender<H3Message>,
    _protocol: Protocol,
) -> UdpResponseSender {
    UdpResponseSender::h3(tx)
}

async fn relay_upstream_to_client_generic<Msg>(
    mut upstream_reader: tokio::net::tcp::OwnedReadHalf,
    outbound_tx: mpsc::Sender<Msg>,
    encryptor: &mut AeadStreamEncryptor,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user_id: Arc<str>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let mut buffer = vec![0_u8; MAX_CHUNK_SIZE];
    loop {
        let read = upstream_reader
            .read(&mut buffer)
            .await
            .context("failed to read from upstream")?;
        if read == 0 {
            break;
        }

        metrics.record_tcp_payload_bytes(Arc::clone(&user_id), protocol, "target_to_client", read);
        let ciphertext = encryptor.encrypt_chunk(&buffer[..read])?;
        outbound_tx
            .send(make_binary(ciphertext.into()))
            .await
            .map_err(|error| anyhow!("failed to queue encrypted websocket frame: {error}"))?;
    }

    outbound_tx.send(make_close()).await.ok();
    Ok(())
}

async fn handle_tcp_binary_frame<Msg>(
    state: &mut TcpRelayState,
    decryptor: &mut AeadStreamDecryptor,
    plaintext_buffer: &mut Vec<u8>,
    data: Bytes,
    outbound_data_tx: &mpsc::Sender<Msg>,
    users: &[UserKey],
    metrics: &Arc<Metrics>,
    protocol: Protocol,
    path: &str,
    candidate_users: &[String],
    prefer_ipv4_upstream: bool,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    metrics.record_websocket_binary_frame(Transport::Tcp, protocol, "in", data.len());
    decryptor.push(&data);
    match decryptor.pull_plaintext(plaintext_buffer) {
        Ok(()) => {}
        Err(CryptoError::UnknownUser) => {
            debug!(
                path = %path,
                candidates = ?candidate_users,
                buffered = decryptor.buffered_data().len(),
                attempts = ?diagnose_stream_handshake(users, decryptor.buffered_data()),
                "tcp authentication failed for all path candidates"
            );
            return Err(anyhow!(
                "no configured key matched the incoming data on tcp path {path} candidates={candidate_users:?}",
            ));
        }
        Err(error) => return Err(anyhow!(error)),
    }

    if state.upstream_writer.is_none() {
        let Some((target, consumed)) = parse_target_addr(plaintext_buffer)? else {
            return Ok(());
        };
        let Some(user) = decryptor.user().cloned() else {
            return Ok(());
        };
        debug!(
            user = user.id(),
            cipher = user.cipher().as_str(),
            path = %path,
            "tcp shadowsocks user authenticated"
        );
        let user_id = user.id_arc();
        let target_display = target.display_host_port();
        let connect_started = std::time::Instant::now();
        let stream = match connect_tcp_target(&target, user.fwmark(), prefer_ipv4_upstream).await {
            Ok(stream) => {
                metrics.record_tcp_connect(
                    Arc::clone(&user_id),
                    protocol,
                    "success",
                    connect_started.elapsed().as_secs_f64(),
                );
                stream
            }
            Err(error) => {
                metrics.record_tcp_connect(
                    Arc::clone(&user_id),
                    protocol,
                    "error",
                    connect_started.elapsed().as_secs_f64(),
                );
                return Err(error)
                    .with_context(|| format!("failed to connect to {target_display}"));
            }
        };
        info!(
            user = user.id(),
            fwmark = ?user.fwmark(),
            path = %path,
            target = %target_display,
            "tcp upstream connected"
        );

        let (upstream_reader, writer) = stream.into_split();
        let mut encryptor = AeadStreamEncryptor::new(&user, decryptor.response_context())?;
        let tx = outbound_data_tx.clone();
        let relay_metrics = Arc::clone(metrics);
        let relay_user_id = Arc::clone(&user_id);
        state.upstream_to_client = Some(tokio::spawn(async move {
            relay_upstream_to_client_generic(
                upstream_reader,
                tx,
                &mut encryptor,
                relay_metrics,
                protocol,
                relay_user_id,
                make_binary,
                make_close,
            )
            .await
        }));
        metrics.record_tcp_authenticated_session(Arc::clone(&user_id), protocol);
        state.upstream_guard = Some(metrics.open_tcp_upstream_connection(user_id, protocol));
        state.authenticated_user = Some(user);
        state.upstream_writer = Some(writer);
        plaintext_buffer.drain(..consumed);
    }

    if let Some(writer) = &mut state.upstream_writer
        && !plaintext_buffer.is_empty()
    {
        if let Some(user) = &state.authenticated_user {
            metrics.record_tcp_payload_bytes(
                user.id_arc(),
                protocol,
                "client_to_target",
                plaintext_buffer.len(),
            );
        }
        writer
            .write_all(plaintext_buffer)
            .await
            .context("failed to write decrypted data upstream")?;
        plaintext_buffer.clear();
    }

    Ok(())
}

async fn handle_udp_datagram_common<Msg>(
    nat_table: Arc<NatTable>,
    users: Arc<[UserKey]>,
    data: Bytes,
    outbound_tx: mpsc::Sender<Msg>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: String,
    candidate_users: Arc<[String]>,
    udp_session_recorded: Arc<AtomicBool>,
    cached_user_index: Arc<AtomicUsize>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
    make_response_sender: fn(mpsc::Sender<Msg>, Protocol) -> UdpResponseSender,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let started_at = std::time::Instant::now();
    let preferred_user_index = match cached_user_index.load(Ordering::Relaxed) {
        UDP_CACHED_USER_INDEX_EMPTY => None,
        index => Some(index),
    };
    let (packet, user_index) = match decrypt_udp_packet_with_hint(
        users.as_ref(),
        &data,
        preferred_user_index,
    ) {
        Ok(result) => result,
        Err(CryptoError::UnknownUser) => {
            debug!(
                path = %path,
                candidates = ?candidate_users,
                attempts = ?diagnose_udp_packet(users.as_ref(), &data),
                "udp authentication failed for all path candidates"
            );
            return Err(anyhow!(
                "no configured key matched the incoming udp data on path {path} candidates={candidate_users:?}",
            ));
        }
        Err(error) => return Err(anyhow!(error)),
    };
    cached_user_index.store(user_index, Ordering::Relaxed);
    let user_id = packet.user.id_arc();
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.display_host_port();
    if udp_session_recorded.swap(true, Ordering::Relaxed) {
        metrics.record_client_last_seen(Arc::clone(&user_id));
    } else {
        metrics.record_client_session(Arc::clone(&user_id), protocol, Transport::Udp);
    }
    debug!(
        user = packet.user.id(),
        cipher = packet.user.cipher().as_str(),
        path = %path,
        "udp shadowsocks user authenticated"
    );

    let resolved =
        resolve_udp_target(udp_dns_cache.as_ref(), &target, prefer_ipv4_upstream).await?;
    info!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        path = %path,
        target = %target_display,
        resolved = %resolved,
        "udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: packet.user.id().to_owned(),
        fwmark: packet.user.fwmark(),
        target: resolved,
        udp_client_session_id: packet.session.client_session_id(),
    };
    let entry = nat_table
        .get_or_create(
            nat_key,
            &packet.user,
            packet.session.clone(),
            Arc::clone(&metrics),
        )
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry
        .register_session(make_response_sender(outbound_tx, protocol))
        .await;

    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        metrics.record_udp_oversized_datagram_dropped(
            Arc::clone(&user_id),
            protocol,
            "client_to_target",
        );
        warn!(
            user = packet.user.id(),
            path = %path,
            target = %resolved,
            plaintext_bytes = payload.len(),
            max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
            "dropping oversized udp datagram before upstream send"
        );
        metrics.record_udp_request(
            Arc::clone(&user_id),
            protocol,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Ok(());
    }
    metrics.record_udp_payload_bytes(
        Arc::clone(&user_id),
        protocol,
        "client_to_target",
        payload.len(),
    );
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        metrics.record_udp_request(
            Arc::clone(&user_id),
            protocol,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    metrics.record_udp_request(
        user_id,
        protocol,
        "success",
        started_at.elapsed().as_secs_f64(),
    );

    Ok(())
}

async fn handle_tcp_connection(
    socket: WebSocket,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: String,
    candidate_users: Arc<[String]>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (outbound_data_tx, mut outbound_data_rx) = mpsc::channel::<Message>(64);
    let (outbound_ctrl_tx, mut outbound_ctrl_rx) = mpsc::channel::<Message>(8);
    let writer_metrics = metrics.clone();
    let writer_task = tokio::spawn(async move {
        let mut ctrl_open = true;
        loop {
            if ctrl_open {
                tokio::select! {
                    biased;
                    msg = outbound_ctrl_rx.recv() => match msg {
                        Some(m) => ws_sender.send(m).await.context("failed to write websocket frame")?,
                        None => ctrl_open = false,
                    },
                    msg = outbound_data_rx.recv() => match msg {
                        Some(m) => {
                            if let Message::Binary(data) = &m {
                                writer_metrics.record_websocket_binary_frame(
                                    Transport::Tcp,
                                    protocol,
                                    "out",
                                    data.len(),
                                );
                            }
                            ws_sender.send(m).await.context("failed to write websocket frame")?;
                        }
                        None => break,
                    },
                }
            } else {
                let Some(m) = outbound_data_rx.recv().await else {
                    break;
                };
                if let Message::Binary(data) = &m {
                    writer_metrics.record_websocket_binary_frame(
                        Transport::Tcp,
                        protocol,
                        "out",
                        data.len(),
                    );
                }
                ws_sender
                    .send(m)
                    .await
                    .context("failed to write websocket frame")?;
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    let mut plaintext_buffer = Vec::with_capacity(MAX_CHUNK_SIZE);
    let mut state = TcpRelayState::new();
    let mut client_closed = false;

    while let Some(message) = ws_receiver.next().await {
        match message.context("websocket receive failure")? {
            Message::Binary(data) => {
                handle_tcp_binary_frame(
                    &mut state,
                    &mut decryptor,
                    &mut plaintext_buffer,
                    data,
                    &outbound_data_tx,
                    users.as_ref(),
                    &metrics,
                    protocol,
                    &path,
                    candidate_users.as_ref(),
                    prefer_ipv4_upstream,
                    ws_binary_message,
                    ws_close_message,
                )
                .await?;
            }
            Message::Close(_) => {
                debug!("client closed tcp websocket");
                client_closed = true;
                break;
            }
            Message::Ping(payload) => {
                outbound_ctrl_tx
                    .send(ws_pong_message(payload))
                    .await
                    .context("failed to queue websocket pong")?;
            }
            Message::Pong(_) => {}
            Message::Text(_) => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    if let Some(mut writer) = state.upstream_writer.take() {
        writer.shutdown().await.ok();
    }

    if client_closed {
        // Client initiated the close; tungstenite state is now ClosedByPeer so
        // ws_sender.send() will fail for any further frames.  Abort the relay
        // task so it cannot queue additional data that the writer can never
        // deliver, then let the writer drain and exit without propagating its
        // error.
        if let Some(task) = state.upstream_to_client.take() {
            task.abort();
        }
        if let Some(guard) = state.upstream_guard.take() {
            guard.finish();
        }
        drop(outbound_ctrl_tx);
        drop(outbound_data_tx);
        let _ = writer_task.await;
    } else {
        if let Some(task) = state.upstream_to_client.take() {
            task.await
                .context("tcp upstream relay task join failed")??;
        }
        if let Some(guard) = state.upstream_guard.take() {
            guard.finish();
        }
        drop(outbound_ctrl_tx);
        drop(outbound_data_tx);
        writer_task
            .await
            .context("websocket writer task join failed")??;
    }
    Ok(())
}

async fn handle_udp_connection(
    socket: WebSocket,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: String,
    candidate_users: Arc<[String]>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (outbound_data_tx, mut outbound_data_rx) = mpsc::channel::<Message>(64);
    let (outbound_ctrl_tx, mut outbound_ctrl_rx) = mpsc::channel::<Message>(8);
    let udp_session_recorded = Arc::new(AtomicBool::new(false));
    let cached_user_index = Arc::new(AtomicUsize::new(UDP_CACHED_USER_INDEX_EMPTY));
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    let writer_metrics = metrics.clone();
    let writer_task = tokio::spawn(async move {
        let mut ctrl_open = true;
        loop {
            if ctrl_open {
                tokio::select! {
                    biased;
                    msg = outbound_ctrl_rx.recv() => match msg {
                        Some(m) => ws_sender.send(m).await.context("failed to write websocket frame")?,
                        None => ctrl_open = false,
                    },
                    msg = outbound_data_rx.recv() => match msg {
                        Some(m) => {
                            if let Message::Binary(data) = &m {
                                writer_metrics.record_websocket_binary_frame(
                                    Transport::Udp,
                                    protocol,
                                    "out",
                                    data.len(),
                                );
                            }
                            ws_sender.send(m).await.context("failed to write websocket frame")?;
                        }
                        None => break,
                    },
                }
            } else {
                let Some(m) = outbound_data_rx.recv().await else {
                    break;
                };
                if let Message::Binary(data) = &m {
                    writer_metrics.record_websocket_binary_frame(
                        Transport::Udp,
                        protocol,
                        "out",
                        data.len(),
                    );
                }
                ws_sender
                    .send(m)
                    .await
                    .context("failed to write websocket frame")?;
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut loop_result = Ok(());
    loop {
        tokio::select! {
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
            message = ws_receiver.next() => {
                let Some(message) = message else { break };
                match message.context("websocket receive failure") {
                    Ok(Message::Binary(data)) => {
                        metrics.record_websocket_binary_frame(Transport::Udp, protocol, "in", data.len());
                        if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                            metrics.record_udp_relay_drop(Transport::Udp, protocol, "concurrency_limit");
                            warn!("udp concurrent relay limit reached, dropping datagram");
                            continue;
                        }
                        let tx = outbound_data_tx.clone();
                        let users = users.clone();
                        let metrics = metrics.clone();
                        let path = path.clone();
                        let candidate_users = candidate_users.clone();
                        let udp_session_recorded = udp_session_recorded.clone();
                        let cached_user_index = Arc::clone(&cached_user_index);
                        let nat_table = Arc::clone(&nat_table);
                        let udp_dns_cache = Arc::clone(&udp_dns_cache);
                        in_flight.push(async move {
                            if let Err(error) = handle_udp_datagram_common(
                                nat_table,
                                users,
                                data,
                                tx,
                                metrics,
                                protocol,
                                path,
                                candidate_users,
                                udp_session_recorded,
                                cached_user_index,
                                udp_dns_cache,
                                prefer_ipv4_upstream,
                                make_ws_udp_response_sender,
                            )
                            .await
                            {
                                warn!(?error, "udp datagram relay failed");
                            }
                        }.boxed());
                    }
                    Ok(Message::Close(_)) => {
                        debug!("client closed udp websocket");
                        break;
                    }
                    Ok(Message::Ping(payload)) => {
                        if let Err(error) = outbound_ctrl_tx
                            .send(ws_pong_message(payload))
                            .await
                            .context("failed to queue websocket pong")
                        {
                            loop_result = Err(error);
                            break;
                        }
                    }
                    Ok(Message::Pong(_)) => {}
                    Ok(Message::Text(_)) => {
                        loop_result = Err(anyhow!("text websocket frames are not supported"));
                        break;
                    }
                    Err(error) => {
                        loop_result = Err(error);
                        break;
                    }
                }
            }
        }
    }

    while in_flight.next().await.is_some() {}
    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    writer_task
        .await
        .context("websocket writer task join failed")??;
    loop_result
}

async fn handle_tcp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    path: String,
    candidate_users: Arc<[String]>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let (mut ws_reader, mut ws_writer) = socket.split();
    let (outbound_data_tx, mut outbound_data_rx) = mpsc::channel::<H3Message>(64);
    let (outbound_ctrl_tx, mut outbound_ctrl_rx) = mpsc::channel::<H3Message>(8);
    let writer_metrics = metrics.clone();
    let writer_task = tokio::spawn(async move {
        let result = async {
            let mut ctrl_open = true;
            loop {
                if ctrl_open {
                    tokio::select! {
                        biased;
                        msg = outbound_ctrl_rx.recv() => match msg {
                            Some(m) => ws_writer.send(m).await.context("failed to write websocket frame")?,
                            None => ctrl_open = false,
                        },
                        msg = outbound_data_rx.recv() => match msg {
                            Some(m) => {
                                if let H3Message::Binary(data) = &m {
                                    writer_metrics.record_websocket_binary_frame(
                                        Transport::Tcp,
                                        Protocol::Http3,
                                        "out",
                                        data.len(),
                                    );
                                }
                                ws_writer.send(m).await.context("failed to write websocket frame")?;
                            }
                            None => break,
                        },
                    }
                } else {
                    let Some(m) = outbound_data_rx.recv().await else {
                        break;
                    };
                    if let H3Message::Binary(data) = &m {
                        writer_metrics.record_websocket_binary_frame(
                            Transport::Tcp,
                            Protocol::Http3,
                            "out",
                            data.len(),
                        );
                    }
                    ws_writer
                        .send(m)
                        .await
                        .context("failed to write websocket frame")?;
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let _ = ws_writer.close(1000, "").await;
        result
    });
    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    let mut plaintext_buffer = Vec::with_capacity(MAX_CHUNK_SIZE);
    let mut state = TcpRelayState::new();

    while let Some(message) = ws_reader.next().await {
        match message.context("websocket receive failure")? {
            H3Message::Binary(data) => {
                handle_tcp_binary_frame(
                    &mut state,
                    &mut decryptor,
                    &mut plaintext_buffer,
                    data,
                    &outbound_data_tx,
                    users.as_ref(),
                    &metrics,
                    Protocol::Http3,
                    &path,
                    candidate_users.as_ref(),
                    prefer_ipv4_upstream,
                    h3_binary_message,
                    h3_close_message,
                )
                .await?;
            }
            H3Message::Close(_) => {
                debug!("client closed tcp websocket");
                break;
            }
            H3Message::Ping(payload) => {
                outbound_ctrl_tx
                    .send(h3_pong_message(payload))
                    .await
                    .context("failed to queue websocket pong")?;
            }
            H3Message::Pong(_) => {}
            H3Message::Text(_) => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    if let Some(mut writer) = state.upstream_writer.take() {
        writer.shutdown().await.ok();
    }

    if let Some(task) = state.upstream_to_client.take() {
        task.await
            .context("tcp upstream relay task join failed")??;
    }

    if let Some(guard) = state.upstream_guard.take() {
        guard.finish();
    }

    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    writer_task
        .await
        .context("websocket writer task join failed")??;
    Ok(())
}

async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    path: String,
    candidate_users: Arc<[String]>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let (mut ws_reader, mut ws_writer) = socket.split();
    let (outbound_data_tx, mut outbound_data_rx) = mpsc::channel::<H3Message>(64);
    let (outbound_ctrl_tx, mut outbound_ctrl_rx) = mpsc::channel::<H3Message>(8);
    let udp_session_recorded = Arc::new(AtomicBool::new(false));
    let cached_user_index = Arc::new(AtomicUsize::new(UDP_CACHED_USER_INDEX_EMPTY));
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    let writer_metrics = metrics.clone();
    let writer_task = tokio::spawn(async move {
        let result = async {
            let mut ctrl_open = true;
            loop {
                if ctrl_open {
                    tokio::select! {
                        biased;
                        msg = outbound_ctrl_rx.recv() => match msg {
                            Some(m) => ws_writer.send(m).await.context("failed to write websocket frame")?,
                            None => ctrl_open = false,
                        },
                        msg = outbound_data_rx.recv() => match msg {
                            Some(m) => {
                                if let H3Message::Binary(data) = &m {
                                    writer_metrics.record_websocket_binary_frame(
                                        Transport::Udp,
                                        Protocol::Http3,
                                        "out",
                                        data.len(),
                                    );
                                }
                                ws_writer.send(m).await.context("failed to write websocket frame")?;
                            }
                            None => break,
                        },
                    }
                } else {
                    let Some(m) = outbound_data_rx.recv().await else {
                        break;
                    };
                    if let H3Message::Binary(data) = &m {
                        writer_metrics.record_websocket_binary_frame(
                            Transport::Udp,
                            Protocol::Http3,
                            "out",
                            data.len(),
                        );
                    }
                    ws_writer
                        .send(m)
                        .await
                        .context("failed to write websocket frame")?;
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        let _ = ws_writer.close(1000, "").await;
        result
    });
    let mut loop_result = Ok(());
    loop {
        tokio::select! {
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
            message = ws_reader.next() => {
                let Some(message) = message else { break };
                match message.context("websocket receive failure") {
                    Ok(H3Message::Binary(data)) => {
                        metrics.record_websocket_binary_frame(
                            Transport::Udp,
                            Protocol::Http3,
                            "in",
                            data.len(),
                        );
                        if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                            metrics.record_udp_relay_drop(
                                Transport::Udp,
                                Protocol::Http3,
                                "concurrency_limit",
                            );
                            warn!("udp concurrent relay limit reached, dropping datagram");
                            continue;
                        }
                        let tx = outbound_data_tx.clone();
                        let users = users.clone();
                        let metrics = metrics.clone();
                        let path = path.clone();
                        let candidate_users = candidate_users.clone();
                        let udp_session_recorded = udp_session_recorded.clone();
                        let cached_user_index = Arc::clone(&cached_user_index);
                        let nat_table = Arc::clone(&nat_table);
                        let udp_dns_cache = Arc::clone(&udp_dns_cache);
                        in_flight.push(async move {
                            if let Err(error) = handle_udp_datagram_common(
                                nat_table,
                                users,
                                data,
                                tx,
                                metrics,
                                Protocol::Http3,
                                path,
                                candidate_users,
                                udp_session_recorded,
                                cached_user_index,
                                udp_dns_cache,
                                prefer_ipv4_upstream,
                                make_h3_udp_response_sender,
                            )
                            .await
                            {
                                warn!(?error, "udp datagram relay failed");
                            }
                        }.boxed());
                    }
                    Ok(H3Message::Close(_)) => {
                        debug!("client closed udp websocket");
                        break;
                    }
                    Ok(H3Message::Ping(payload)) => {
                        if let Err(error) = outbound_ctrl_tx
                            .send(h3_pong_message(payload))
                            .await
                            .context("failed to queue websocket pong")
                        {
                            loop_result = Err(error);
                            break;
                        }
                    }
                    Ok(H3Message::Pong(_)) => {}
                    Ok(H3Message::Text(_)) => {
                        loop_result = Err(anyhow!("text websocket frames are not supported"));
                        break;
                    }
                    Err(error) => {
                        loop_result = Err(error);
                        break;
                    }
                }
            }
        }
    }

    while in_flight.next().await.is_some() {}
    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    writer_task
        .await
        .context("websocket writer task join failed")??;
    loop_result
}

async fn resolve_target(target: &TargetAddr, prefer_ipv4_upstream: bool) -> Result<SocketAddr> {
    resolve_target_addrs(target, prefer_ipv4_upstream)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            anyhow!(
                "dns lookup returned no records for {}",
                target.display_host_port()
            )
        })
}

async fn resolve_udp_target(
    udp_dns_cache: &UdpDnsCache,
    target: &TargetAddr,
    prefer_ipv4_upstream: bool,
) -> Result<SocketAddr> {
    match target {
        TargetAddr::Domain(host, port) => {
            if let Some(resolved) = udp_dns_cache.lookup(host, *port, prefer_ipv4_upstream) {
                return Ok(resolved);
            }
            let resolved = resolve_target(target, prefer_ipv4_upstream).await?;
            udp_dns_cache.store(host, *port, prefer_ipv4_upstream, resolved);
            Ok(resolved)
        }
        TargetAddr::Socket(_) => resolve_target(target, prefer_ipv4_upstream).await,
    }
}

async fn resolve_target_addrs(
    target: &TargetAddr,
    prefer_ipv4_upstream: bool,
) -> Result<Vec<SocketAddr>> {
    match target {
        TargetAddr::Socket(addr) => {
            if prefer_ipv4_upstream && addr.is_ipv6() {
                return Err(anyhow!(
                    "ipv6 upstream disabled by prefer_ipv4_upstream for {}",
                    addr
                ));
            }
            Ok(vec![*addr])
        }
        TargetAddr::Domain(host, port) => {
            let mut addrs = lookup_host((host.as_str(), *port))
                .await
                .with_context(|| format!("dns lookup failed for {host}:{port}"))?
                .collect::<Vec<_>>();
            if prefer_ipv4_upstream {
                addrs.retain(SocketAddr::is_ipv4);
            }
            if addrs.is_empty() {
                return Err(anyhow!("dns lookup returned no records for {host}:{port}"));
            }
            Ok(addrs)
        }
    }
}

async fn connect_tcp_target(
    target: &TargetAddr,
    fwmark: Option<u32>,
    prefer_ipv4_upstream: bool,
) -> Result<TcpStream> {
    let resolved = order_tcp_connect_addrs(
        resolve_target_addrs(target, prefer_ipv4_upstream).await?,
        prefer_ipv4_upstream,
    );
    connect_tcp_addrs(&resolved, fwmark)
        .await
        .with_context(|| format!("tcp connect failed for {}", target.display_host_port()))
}

fn order_tcp_connect_addrs(addrs: Vec<SocketAddr>, prefer_ipv4_upstream: bool) -> Vec<SocketAddr> {
    let prefer_ipv6 = if prefer_ipv4_upstream {
        false
    } else {
        addrs.first().is_some_and(SocketAddr::is_ipv6)
    };
    let mut seen = HashSet::with_capacity(addrs.len());
    let mut ipv4 = VecDeque::new();
    let mut ipv6 = VecDeque::new();

    for addr in addrs {
        if !seen.insert(addr) {
            continue;
        }
        if addr.is_ipv6() {
            ipv6.push_back(addr);
        } else {
            ipv4.push_back(addr);
        }
    }

    let (primary, secondary) = if prefer_ipv6 {
        (&mut ipv6, &mut ipv4)
    } else {
        (&mut ipv4, &mut ipv6)
    };
    let mut ordered = Vec::with_capacity(primary.len() + secondary.len());
    while let Some(addr) = primary.pop_front() {
        ordered.push(addr);
        if let Some(fallback_addr) = secondary.pop_front() {
            ordered.push(fallback_addr);
        }
    }
    ordered.extend(secondary.drain(..));
    ordered
}

async fn connect_tcp_addrs(addrs: &[SocketAddr], fwmark: Option<u32>) -> Result<TcpStream> {
    let mut attempts = FuturesUnordered::new();
    for (index, addr) in addrs.iter().copied().enumerate() {
        attempts.push(async move {
            if index > 0 {
                tokio::time::sleep(Duration::from_millis(
                    TCP_HAPPY_EYEBALLS_DELAY_MS * index as u64,
                ))
                .await;
            }
            let result = connect_tcp_addr(addr, fwmark).await;
            (addr, result)
        });
    }

    let mut last_error = None;
    while let Some((addr, result)) = attempts.next().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some((addr, error)),
        }
    }

    match last_error {
        Some((addr, error)) => Err(error)
            .with_context(|| format!("all tcp connect attempts failed; last address {addr}")),
        None => Err(anyhow!("no socket addresses available for tcp connect")),
    }
}

async fn connect_tcp_addr(resolved: SocketAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    let socket = if resolved.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .with_context(|| format!("failed to create tcp socket for {resolved}"))?;

    apply_fwmark_if_needed(&socket, fwmark)
        .with_context(|| format!("failed to apply fwmark {fwmark:?} to tcp socket"))?;

    match timeout(
        Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS),
        socket.connect(resolved),
    )
    .await
    {
        Ok(Ok(stream)) => {
            configure_tcp_stream(&stream)
                .with_context(|| format!("failed to configure tcp stream for {resolved}"))?;
            Ok(stream)
        }
        Ok(Err(error)) => Err(error).with_context(|| format!("tcp connect failed for {resolved}")),
        Err(_) => Err(anyhow!(
            "tcp connect timed out after {}s for {resolved}",
            TCP_CONNECT_TIMEOUT_SECS
        )),
    }
}

fn configure_tcp_stream(stream: &TcpStream) -> Result<()> {
    stream
        .set_nodelay(true)
        .context("failed to enable TCP_NODELAY")
}

async fn serve_ss_tcp_listener(
    listener: TcpListener,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .context("failed to accept shadowsocks tcp connection")?;
        configure_tcp_stream(&stream).with_context(|| {
            format!("failed to configure accepted shadowsocks tcp connection from {peer}")
        })?;
        let users = users.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_ss_tcp_connection(stream, users, metrics, prefer_ipv4_upstream).await
            {
                if is_benign_ws_disconnect(&error) {
                    debug!(%peer, ?error, "shadowsocks tcp connection closed abruptly");
                } else {
                    warn!(%peer, ?error, "shadowsocks tcp connection terminated with error");
                }
            }
        });
    }
}

async fn handle_ss_tcp_connection(
    socket: TcpStream,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let peer_addr = socket.peer_addr().ok();
    let (mut client_reader, client_writer) = socket.into_split();
    let mut client_writer = Some(client_writer);
    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    let mut plaintext_buffer = Vec::with_capacity(MAX_CHUNK_SIZE);
    let mut upstream_writer = None;
    let mut upstream_to_client = None;
    let mut authenticated_user = None;
    let mut upstream_guard = None;
    let mut read_buffer = vec![0_u8; MAX_CHUNK_SIZE];
    let client_sent_eof;

    loop {
        let read = client_reader
            .read(&mut read_buffer)
            .await
            .context("failed to read from shadowsocks client")?;
        if read == 0 {
            debug!(peer_addr = ?peer_addr, "socket tcp client closed connection");
            client_sent_eof = true;
            break;
        }

        debug!(
            peer_addr = ?peer_addr,
            encrypted_bytes = read,
            buffered_before = decryptor.buffered_data().len(),
            "socket tcp received encrypted bytes"
        );

        decryptor.push(&read_buffer[..read]);
        match decryptor.pull_plaintext(&mut plaintext_buffer) {
            Ok(()) => {
                debug!(
                    peer_addr = ?peer_addr,
                    plaintext_buffer_len = plaintext_buffer.len(),
                    buffered_after = decryptor.buffered_data().len(),
                    authenticated_user = decryptor.user().map(|user| user.id()),
                    "socket tcp decrypted client bytes"
                );
            }
            Err(CryptoError::UnknownUser) => {
                debug!(
                    peer_addr = ?peer_addr,
                    buffered = decryptor.buffered_data().len(),
                    attempts = ?diagnose_stream_handshake(users.as_ref(), decryptor.buffered_data()),
                    "socket tcp authentication failed for all configured users"
                );
                return Err(anyhow!(
                    "no configured key matched the incoming socket tcp stream"
                ));
            }
            Err(error) => return Err(anyhow!(error)),
        }

        if upstream_writer.is_none() {
            let Some((target, consumed)) = parse_target_addr(&plaintext_buffer)? else {
                continue;
            };
            let Some(user) = decryptor.user().cloned() else {
                continue;
            };
            debug!(
                peer_addr = ?peer_addr,
                user = user.id(),
                cipher = user.cipher().as_str(),
                "socket tcp shadowsocks user authenticated"
            );
            let target_display = target.display_host_port();
            debug!(
                peer_addr = ?peer_addr,
                user = user.id(),
                target = %target_display,
                initial_payload_bytes = plaintext_buffer.len().saturating_sub(consumed),
                "socket tcp parsed target address"
            );
            let connect_started = std::time::Instant::now();
            let stream =
                match connect_tcp_target(&target, user.fwmark(), prefer_ipv4_upstream).await {
                    Ok(stream) => {
                        metrics.record_tcp_connect(
                            user.id_arc(),
                            Protocol::Socket,
                            "success",
                            connect_started.elapsed().as_secs_f64(),
                        );
                        stream
                    }
                    Err(error) => {
                        metrics.record_tcp_connect(
                            user.id_arc(),
                            Protocol::Socket,
                            "error",
                            connect_started.elapsed().as_secs_f64(),
                        );
                        return Err(error)
                            .with_context(|| format!("failed to connect to {target_display}"));
                    }
                };
            info!(
                peer_addr = ?peer_addr,
                user = user.id(),
                fwmark = ?user.fwmark(),
                target = %target_display,
                "socket tcp upstream connected"
            );

            let (upstream_reader, writer) = stream.into_split();
            let mut encryptor = AeadStreamEncryptor::new(&user, decryptor.response_context())?;
            let client_writer = client_writer
                .take()
                .ok_or_else(|| anyhow!("socket tcp client writer missing"))?;
            let relay_metrics = metrics.clone();
            let user_id = user.id_arc();
            upstream_to_client = Some(tokio::spawn(async move {
                relay_upstream_to_socket_client(
                    upstream_reader,
                    client_writer,
                    &mut encryptor,
                    relay_metrics,
                    user_id,
                )
                .await
            }));
            metrics.record_tcp_authenticated_session(user.id_arc(), Protocol::Socket);
            upstream_guard =
                Some(metrics.open_tcp_upstream_connection(user.id_arc(), Protocol::Socket));
            authenticated_user = Some(user);
            upstream_writer = Some(writer);
            plaintext_buffer.drain(..consumed);
        }

        if let Some(writer) = &mut upstream_writer
            && !plaintext_buffer.is_empty()
        {
            if let Some(user) = &authenticated_user {
                metrics.record_tcp_payload_bytes(
                    user.id_arc(),
                    Protocol::Socket,
                    "client_to_target",
                    plaintext_buffer.len(),
                );
                debug!(
                    peer_addr = ?peer_addr,
                    user = user.id(),
                    plaintext_bytes = plaintext_buffer.len(),
                    "socket tcp relaying plaintext to upstream"
                );
            }
            writer
                .write_all(&plaintext_buffer)
                .await
                .context("failed to write decrypted data upstream")?;
            plaintext_buffer.clear();
        }
    }

    if let Some(mut writer) = upstream_writer {
        writer.shutdown().await.ok();
    }

    if let Some(task) = upstream_to_client {
        if client_sent_eof {
            task.await
                .context("socket tcp upstream relay task join failed after client eof")??;
        } else {
            task.abort();
        }
    }

    if let Some(guard) = upstream_guard {
        guard.finish();
    }
    Ok(())
}

async fn relay_upstream_to_socket_client(
    mut upstream_reader: tokio::net::tcp::OwnedReadHalf,
    mut client_writer: tokio::net::tcp::OwnedWriteHalf,
    encryptor: &mut AeadStreamEncryptor,
    metrics: Arc<Metrics>,
    user_id: Arc<str>,
) -> Result<()> {
    let mut buffer = vec![0_u8; MAX_CHUNK_SIZE];
    loop {
        let read = upstream_reader
            .read(&mut buffer)
            .await
            .context("failed to read from upstream")?;
        if read == 0 {
            break;
        }

        metrics.record_tcp_payload_bytes(
            Arc::clone(&user_id),
            Protocol::Socket,
            "target_to_client",
            read,
        );
        let ciphertext = encryptor.encrypt_chunk(&buffer[..read])?;
        debug!(
            user = %user_id,
            plaintext_bytes = read,
            encrypted_bytes = ciphertext.len(),
            "socket tcp relaying upstream bytes to client"
        );
        client_writer
            .write_all(&ciphertext)
            .await
            .context("failed to write encrypted socket payload")?;
    }

    client_writer.shutdown().await.ok();
    Ok(())
}

async fn serve_ss_udp_socket(
    socket: Arc<UdpSocket>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let mut in_flight: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
    let mut buffer = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
            recv = socket.recv_from(&mut buffer) => {
                let (read, client_addr) = recv.context("failed to receive shadowsocks udp packet")?;
                debug!(
                    client_addr = %client_addr,
                    encrypted_bytes = read,
                    "socket udp received encrypted datagram"
                );
                if in_flight.len() >= UDP_MAX_CONCURRENT_RELAY_TASKS {
                    metrics.record_udp_relay_drop(
                        Transport::Udp,
                        Protocol::Socket,
                        "concurrency_limit",
                    );
                    warn!(%client_addr, "socket udp concurrent relay limit reached, dropping datagram");
                    continue;
                }
                let data = Bytes::copy_from_slice(&buffer[..read]);
                let users = users.clone();
                let metrics = metrics.clone();
                let nat_table = Arc::clone(&nat_table);
                let socket = Arc::clone(&socket);
                let udp_dns_cache = Arc::clone(&udp_dns_cache);
                in_flight.push(async move {
                    if let Err(error) = handle_ss_udp_datagram(
                        nat_table,
                        users,
                        data,
                        client_addr,
                        socket,
                        metrics,
                        udp_dns_cache,
                        prefer_ipv4_upstream,
                    )
                    .await
                    {
                        warn!(%client_addr, ?error, "socket udp datagram relay failed");
                    }
                }.boxed());
            }
        }
    }
}

async fn handle_ss_udp_datagram(
    nat_table: Arc<NatTable>,
    users: Arc<[UserKey]>,
    data: Bytes,
    client_addr: SocketAddr,
    outbound_socket: Arc<UdpSocket>,
    metrics: Arc<Metrics>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let started_at = std::time::Instant::now();
    let packet = match decrypt_udp_packet(users.as_ref(), &data) {
        Ok(packet) => packet,
        Err(CryptoError::UnknownUser) => {
            debug!(
                client_addr = %client_addr,
                encrypted_bytes = data.len(),
                attempts = ?diagnose_udp_packet(users.as_ref(), &data),
                "socket udp authentication failed for all configured users"
            );
            return Err(anyhow!(
                "no configured key matched the incoming socket udp datagram"
            ));
        }
        Err(error) => return Err(anyhow!(error)),
    };
    let user_id = packet.user.id_arc();
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.display_host_port();
    metrics.record_client_last_seen(Arc::clone(&user_id));
    debug!(
        user = packet.user.id(),
        cipher = packet.user.cipher().as_str(),
        client_addr = %client_addr,
        plaintext_bytes = payload.len(),
        "socket udp shadowsocks user authenticated"
    );

    let resolved =
        resolve_udp_target(udp_dns_cache.as_ref(), &target, prefer_ipv4_upstream).await?;
    debug!(
        user = packet.user.id(),
        client_addr = %client_addr,
        target = %target_display,
        resolved = %resolved,
        plaintext_bytes = payload.len(),
        "socket udp resolved target"
    );
    info!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        client_addr = %client_addr,
        target = %target_display,
        resolved = %resolved,
        "socket udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: packet.user.id().to_owned(),
        fwmark: packet.user.fwmark(),
        target: resolved,
        udp_client_session_id: packet.session.client_session_id(),
    };
    let entry = nat_table
        .get_or_create(
            nat_key,
            &packet.user,
            packet.session.clone(),
            Arc::clone(&metrics),
        )
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry
        .register_session(UdpResponseSender::datagram(outbound_socket, client_addr))
        .await;

    if payload.len() > MAX_UDP_PAYLOAD_SIZE {
        metrics.record_udp_oversized_datagram_dropped(
            Arc::clone(&user_id),
            Protocol::Socket,
            "client_to_target",
        );
        warn!(
            user = packet.user.id(),
            client_addr = %client_addr,
            target = %resolved,
            plaintext_bytes = payload.len(),
            max_udp_payload_bytes = MAX_UDP_PAYLOAD_SIZE,
            "dropping oversized socket udp datagram before upstream send"
        );
        metrics.record_udp_request(
            Arc::clone(&user_id),
            Protocol::Socket,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Ok(());
    }
    metrics.record_udp_payload_bytes(
        Arc::clone(&user_id),
        Protocol::Socket,
        "client_to_target",
        payload.len(),
    );
    debug!(
        user = packet.user.id(),
        client_addr = %client_addr,
        target = %resolved,
        plaintext_bytes = payload.len(),
        "socket udp relaying datagram to upstream"
    );
    if let Err(error) = entry.socket().send_to(payload, resolved).await {
        metrics.record_udp_request(
            Arc::clone(&user_id),
            Protocol::Socket,
            "error",
            started_at.elapsed().as_secs_f64(),
        );
        return Err(error).with_context(|| format!("failed to send UDP datagram to {resolved}"));
    }
    entry.touch();
    metrics.record_udp_request(
        user_id,
        Protocol::Socket,
        "success",
        started_at.elapsed().as_secs_f64(),
    );

    Ok(())
}

fn is_benign_ws_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("Connection reset without closing handshake")
            || message.contains("Connection reset by peer")
            || message.contains("Broken pipe")
            || message.contains("connection closed before message completed")
            || message.contains("Sending after closing is not allowed")
            || message.contains("peer closed connection without sending TLS close_notify")
            || message.contains("ApplicationClose: H3_NO_ERROR")
            || message.contains("Remote error: ApplicationClose: H3_NO_ERROR")
            || message.contains("ApplicationClose: 0x0")
            || message.contains(
                "InternalError in the quic trait implementation: internal error in the http stack",
            )
            || message.contains("Connection error: Timeout")
    })
}

fn is_normal_h3_shutdown(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("ApplicationClose: H3_NO_ERROR")
            || message.contains("Remote error: ApplicationClose: H3_NO_ERROR")
            || message.contains("ApplicationClose: 0x0")
    })
}

fn empty_transport_route() -> TransportRoute {
    TransportRoute {
        users: Arc::from(Vec::<UserKey>::new().into_boxed_slice()),
        candidate_users: Arc::from(Vec::<String>::new().into_boxed_slice()),
    }
}

fn build_transport_route_map(
    users: &[UserKey],
    transport: Transport,
) -> BTreeMap<String, TransportRoute> {
    let mut grouped = BTreeMap::<String, Vec<UserKey>>::new();
    for user in users {
        let path = match transport {
            Transport::Tcp => user.ws_path_tcp(),
            Transport::Udp => user.ws_path_udp(),
        };
        grouped
            .entry(path.to_owned())
            .or_default()
            .push(user.clone());
    }

    grouped
        .into_iter()
        .map(|(path, path_users)| {
            let candidate_users = path_users
                .iter()
                .map(|user| format!("{}:{}", user.id(), user.cipher().as_str()))
                .collect::<Vec<_>>();
            (
                path,
                TransportRoute {
                    users: Arc::from(path_users.into_boxed_slice()),
                    candidate_users: Arc::from(candidate_users.into_boxed_slice()),
                },
            )
        })
        .collect()
}

fn describe_user_routes(users: &[UserKey]) -> Vec<String> {
    users
        .iter()
        .map(|user| {
            format!(
                "{}:{} tcp={} udp={}",
                user.id(),
                user.cipher().as_str(),
                user.ws_path_tcp(),
                user.ws_path_udp()
            )
        })
        .collect()
}

fn build_users(config: &Config) -> Result<Arc<[UserKey]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            .map(|entry| {
                let method = entry.effective_method(config.method);
                let ws_path_tcp = entry.effective_ws_path_tcp(&config.ws_path_tcp).to_owned();
                let ws_path_udp = entry.effective_ws_path_udp(&config.ws_path_udp).to_owned();
                UserKey::new(
                    entry.id,
                    &entry.password,
                    entry.fwmark,
                    method,
                    ws_path_tcp,
                    ws_path_udp,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}

fn build_app(
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
) -> Router {
    let state = AppState {
        tcp_routes: tcp_routes.clone(),
        udp_routes: udp_routes.clone(),
        metrics,
        nat_table,
        udp_dns_cache,
        prefer_ipv4_upstream,
    };
    let mut router = Router::new();

    for path in tcp_routes.keys() {
        // HTTP/1.1 WebSocket uses GET, while RFC 8441 over HTTP/2 uses CONNECT.
        router = router.route(path, any(tcp_websocket_upgrade));
    }

    for path in udp_routes.keys() {
        router = router.route(path, any(udp_websocket_upgrade));
    }

    router.with_state(state)
}

fn build_metrics_app(metrics: Arc<Metrics>, metrics_path: String) -> Router {
    Router::new()
        .route(&metrics_path, any(metrics_handler))
        .with_state(metrics)
}

async fn build_h3_server(config: &Config) -> Result<H3WebSocketServer<H3Transport>> {
    let listen = config
        .effective_h3_listen()
        .ok_or_else(|| anyhow!("h3 server requested without tls configuration"))?;
    let tls_config = load_h3_tls_config(config)?;
    let ws_config = build_h3_ws_config();
    let server_config = build_h3_quinn_server_config(tls_config)?;
    let socket = bind_h3_udp_socket(listen)?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(H3_MAX_UDP_PAYLOAD_SIZE)
        .context("invalid H3 max UDP payload size")?;
    let endpoint = quinn::Endpoint::new(
        endpoint_config,
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("failed to create HTTP/3 QUIC endpoint")?;
    Ok(H3WebSocketServer::<H3Transport>::from_endpoint(
        endpoint, ws_config,
    ))
}

fn build_h3_ws_config() -> H3WebSocketConfig {
    H3WebSocketConfig::builder()
        .idle_timeout(H3_QUIC_IDLE_TIMEOUT_SECS as u32)
        .ping_interval(H3_QUIC_PING_INTERVAL_SECS as u32)
        .max_backpressure(H3_MAX_BACKPRESSURE_BYTES)
        .write_buffer_size(H3_WRITE_BUFFER_BYTES)
        .http3_idle_timeout(H3_QUIC_IDLE_TIMEOUT_SECS * 1_000)
        .http3_stream_window_size(H3_STREAM_WINDOW_BYTES)
        .http3_enable_connect_protocol(true)
        .http3_max_udp_payload_size(H3_MAX_UDP_PAYLOAD_SIZE)
        .build()
}

fn build_h3_quinn_server_config(tls_config: rustls::ServerConfig) -> Result<quinn::ServerConfig> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|_| anyhow!("invalid HTTP/3 TLS config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    server_config.transport_config(Arc::new(build_h3_transport_config()?));
    Ok(server_config)
}

fn build_h3_transport_config() -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(H3_MAX_CONCURRENT_BIDI_STREAMS))
        .max_concurrent_uni_streams(quinn::VarInt::from_u32(H3_MAX_CONCURRENT_UNI_STREAMS))
        .max_idle_timeout(Some(
            Duration::from_secs(H3_QUIC_IDLE_TIMEOUT_SECS)
                .try_into()
                .context("invalid HTTP/3 idle timeout")?,
        ))
        .stream_receive_window(quinn::VarInt::from_u32(
            u32::try_from(H3_STREAM_WINDOW_BYTES).expect("H3_STREAM_WINDOW_BYTES exceeds u32"),
        ))
        .receive_window(quinn::VarInt::from_u32(
            u32::try_from(H3_CONNECTION_WINDOW_BYTES)
                .expect("H3_CONNECTION_WINDOW_BYTES exceeds u32"),
        ))
        .send_window(H3_CONNECTION_WINDOW_BYTES)
        .datagram_receive_buffer_size(Some(H3_CONNECTION_WINDOW_BYTES as usize))
        .datagram_send_buffer_size(H3_CONNECTION_WINDOW_BYTES as usize);
    Ok(transport)
}

fn bind_h3_udp_socket(listen: std::net::SocketAddr) -> Result<std::net::UdpSocket> {
    let domain = if listen.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("failed to create HTTP/3 UDP socket")?;
    socket
        .set_recv_buffer_size(H3_UDP_SOCKET_BUFFER_BYTES)
        .context("failed to set HTTP/3 UDP receive buffer")?;
    if let Ok(actual) = socket.recv_buffer_size() {
        if actual < H3_UDP_SOCKET_BUFFER_BYTES {
            tracing::warn!(
                requested = H3_UDP_SOCKET_BUFFER_BYTES,
                actual,
                "HTTP/3 UDP receive buffer capped by OS — increase net.core.rmem_max (Linux) \
                 or kern.ipc.maxsockbuf (macOS) to reduce packet drops"
            );
        }
    }
    socket
        .set_send_buffer_size(H3_UDP_SOCKET_BUFFER_BYTES)
        .context("failed to set HTTP/3 UDP send buffer")?;
    if let Ok(actual) = socket.send_buffer_size() {
        if actual < H3_UDP_SOCKET_BUFFER_BYTES {
            tracing::warn!(
                requested = H3_UDP_SOCKET_BUFFER_BYTES,
                actual,
                "HTTP/3 UDP send buffer capped by OS — increase net.core.wmem_max (Linux) \
                 or kern.ipc.maxsockbuf (macOS) to reduce packet drops"
            );
        }
    }
    socket
        .bind(&socket2::SockAddr::from(listen))
        .with_context(|| format!("failed to bind HTTP/3 UDP socket {listen}"))?;
    let socket: std::net::UdpSocket = socket.into();
    socket
        .set_nonblocking(true)
        .context("failed to set HTTP/3 UDP socket nonblocking mode")?;
    Ok(socket)
}

async fn serve_tcp_listener(listener: TcpListener, app: Router, config: Arc<Config>) -> Result<()> {
    if config.tcp_tls_enabled() {
        let acceptor = build_tcp_tls_acceptor(config.as_ref())?;
        serve_tls_listener(listener, app, acceptor).await
    } else {
        serve_listener(listener, app).await
    }
}

async fn serve_h3_server(
    server: H3WebSocketServer<H3Transport>,
    tcp_routes: Arc<BTreeMap<String, TransportRoute>>,
    udp_routes: Arc<BTreeMap<String, TransportRoute>>,
    metrics: Arc<Metrics>,
    nat_table: Arc<NatTable>,
    udp_dns_cache: Arc<UdpDnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let tcp_paths = tcp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let udp_paths = udp_routes.keys().cloned().collect::<BTreeSet<_>>();
    let allowed_tcp = tcp_paths.clone();
    let allowed_udp = udp_paths.clone();

    server
        .serve_with_filter(
            move |req: &H3ExtendedConnectRequest| {
                allowed_tcp.contains(req.path.as_str()) || allowed_udp.contains(req.path.as_str())
            },
            move |socket, req| {
                let tcp_routes = tcp_routes.clone();
                let udp_routes = udp_routes.clone();
                let metrics = metrics.clone();
                let tcp_paths = tcp_paths.clone();
                let udp_paths = udp_paths.clone();
                let nat_table = Arc::clone(&nat_table);
                let udp_dns_cache = Arc::clone(&udp_dns_cache);
                async move {
                    if tcp_paths.contains(req.path.as_str()) {
                        let route = tcp_routes
                            .get(&req.path)
                            .cloned()
                            .unwrap_or_else(empty_transport_route);
                        debug!(method = "CONNECT", version = "HTTP/3", path = %req.path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
                        let session = metrics
                            .open_websocket_session(Transport::Tcp, Protocol::Http3);
                        let outcome = match handle_tcp_h3_connection(
                            socket,
                            route.users,
                            metrics.clone(),
                            req.path.clone(),
                            route.candidate_users,
                            prefer_ipv4_upstream,
                        )
                        .await
                        {
                            Ok(()) => DisconnectReason::Normal,
                            Err(error) => {
                                if is_normal_h3_shutdown(&error) {
                                    debug!(?error, "tcp websocket connection closed normally");
                                    DisconnectReason::Normal
                                } else if is_benign_ws_disconnect(&error) {
                                    debug!(?error, "tcp websocket connection closed abruptly");
                                    DisconnectReason::ClientDisconnect
                                } else {
                                    warn!(?error, "tcp websocket connection terminated with error");
                                    DisconnectReason::Error
                                }
                            }
                        };
                        session.finish(outcome);
                    } else if udp_paths.contains(req.path.as_str()) {
                        let route = udp_routes
                            .get(&req.path)
                            .cloned()
                            .unwrap_or_else(empty_transport_route);
                        debug!(method = "CONNECT", version = "HTTP/3", path = %req.path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
                        let session = metrics
                            .open_websocket_session(Transport::Udp, Protocol::Http3);
                        let outcome = match handle_udp_h3_connection(
                            socket,
                            route.users,
                            metrics.clone(),
                            req.path.clone(),
                            route.candidate_users,
                            nat_table,
                            udp_dns_cache,
                            prefer_ipv4_upstream,
                        )
                        .await
                        {
                            Ok(()) => DisconnectReason::Normal,
                            Err(error) => {
                                if is_normal_h3_shutdown(&error) {
                                    debug!(?error, "udp websocket connection closed normally");
                                    DisconnectReason::Normal
                                } else if is_benign_ws_disconnect(&error) {
                                    debug!(?error, "udp websocket connection closed abruptly");
                                    DisconnectReason::ClientDisconnect
                                } else {
                                    warn!(?error, "udp websocket connection terminated with error");
                                    DisconnectReason::Error
                                }
                            }
                        };
                        session.finish(outcome);
                    }
                }
            },
        )
        .await
        .context("HTTP/3 server exited unexpectedly")
}

fn load_h3_tls_config(config: &Config) -> Result<rustls::ServerConfig> {
    let cert_path = config
        .h3_cert_path
        .as_deref()
        .ok_or_else(|| anyhow!("missing h3_cert_path"))?;
    let key_path = config
        .h3_key_path
        .as_deref()
        .ok_or_else(|| anyhow!("missing h3_key_path"))?;

    load_server_tls_config(cert_path, key_path, &[b"h3".as_slice()])
        .context("failed to build HTTP/3 TLS config")
}

fn build_tcp_tls_acceptor(config: &Config) -> Result<TlsAcceptor> {
    let cert_path = config
        .tls_cert_path
        .as_deref()
        .ok_or_else(|| anyhow!("missing tls_cert_path"))?;
    let key_path = config
        .tls_key_path
        .as_deref()
        .ok_or_else(|| anyhow!("missing tls_key_path"))?;

    let tls_config = load_server_tls_config(
        cert_path,
        key_path,
        &[b"h2".as_slice(), b"http/1.1".as_slice()],
    )
    .context("failed to build TCP TLS config")?;

    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

fn load_server_tls_config(
    cert_path: &Path,
    key_path: &Path,
    alpn_protocols: &[&[u8]],
) -> Result<rustls::ServerConfig> {
    ensure_rustls_provider_installed();
    let certs = load_cert_chain(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_config.alpn_protocols = alpn_protocols.iter().map(|alpn| alpn.to_vec()).collect();
    Ok(tls_config)
}

fn ensure_rustls_provider_installed() {
    static RUSTLS_PROVIDER: OnceLock<()> = OnceLock::new();
    RUSTLS_PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("der"))
    {
        return Ok(vec![CertificateDer::from(pem)]);
    }

    rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificate chain {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("der"))
    {
        return PrivateKeyDer::try_from(key)
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("failed to parse private key {}", path.display()));
    }

    rustls_pemfile::private_key(&mut key.as_slice())
        .with_context(|| format!("failed to parse private key {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

async fn serve_listener(listener: TcpListener, app: Router) -> Result<()> {
    let listener = listener.tap_io(|stream| {
        if let Err(error) = configure_tcp_stream(stream) {
            warn!(?error, "failed to configure accepted http connection");
        }
    });
    axum::serve(listener, app)
        .await
        .context("server exited unexpectedly")
}

async fn serve_metrics_listener(listener: TcpListener, app: Router) -> Result<()> {
    axum::serve(listener, app)
        .await
        .context("metrics server exited unexpectedly")
}

async fn serve_tls_listener(
    listener: TcpListener,
    app: Router,
    acceptor: TlsAcceptor,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept TLS tcp connection")?;
        configure_tcp_stream(&stream).with_context(|| {
            format!("failed to configure accepted TLS tcp connection from {peer_addr}")
        })?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    warn!(?error, %peer_addr, "tls handshake failed");
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service = TowerToHyperService::new(app);
            let builder = build_http_server_builder();

            if let Err(error) = builder.serve_connection_with_upgrades(io, service).await {
                if !is_benign_http_serve_error(error.as_ref()) {
                    warn!(?error, %peer_addr, "tls http server connection terminated with error");
                }
            }
        });
    }
}

fn build_http_server_builder() -> HyperBuilder<TokioExecutor> {
    let mut builder = HyperBuilder::new(TokioExecutor::new());
    builder
        .http2()
        .enable_connect_protocol()
        .initial_stream_window_size(Some(H2_STREAM_WINDOW_BYTES))
        .initial_connection_window_size(Some(H2_CONNECTION_WINDOW_BYTES))
        .max_send_buf_size(H2_MAX_SEND_BUF_SIZE)
        .keep_alive_interval(Some(Duration::from_secs(H2_KEEPALIVE_INTERVAL_SECS)))
        .keep_alive_timeout(Duration::from_secs(H2_KEEPALIVE_TIMEOUT_SECS));
    builder
}

fn is_benign_http_serve_error(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    let message = error.to_string();
    message.contains("connection closed")
        || message.contains("closed before message completed")
        || message.contains("canceled")
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::Arc,
    };

    use anyhow::Result;
    use axum::http::{Method, Request, StatusCode, Version, header};
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use h3::ext::Protocol as H3Protocol;
    use http_body_util::Empty;
    use hyper::ext::Protocol;
    use hyper_util::{
        client::legacy::Client,
        rt::{TokioExecutor, TokioIo},
    };
    use quinn::Endpoint;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use sockudo_ws::{
        Config as H3WsConfig, Http3 as H3Transport, Message as H3Message, Role as H3Role,
        Stream as H3Stream, WebSocketServer as H3WebSocketServer,
        WebSocketStream as H3WebSocketStream,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream, UdpSocket},
    };
    use tokio_tungstenite::{
        WebSocketStream, connect_async,
        tungstenite::{Message as WsMessage, protocol},
    };

    use super::{
        UdpDnsCache, build_app, build_transport_route_map, build_users, connect_tcp_addrs,
        connect_tcp_target, order_tcp_connect_addrs, serve_h3_server, serve_listener,
        serve_ss_tcp_listener, serve_ss_udp_socket,
    };
    use crate::config::{CipherKind, Config, UserEntry};
    use crate::crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, decrypt_udp_packet, encrypt_udp_packet,
    };
    use crate::metrics::{Metrics, Transport};
    use crate::nat::NatTable;
    use crate::protocol::TargetAddr;

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
        let mut client = connect_tcp_target(&target, None, false).await?;
        client.write_all(b"ping").await?;

        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).await?;

        assert_eq!(&reply, b"pong");
        assert_eq!(server.await??, *b"ping");
        Ok(())
    }

    #[test]
    fn tcp_connect_order_interleaves_ipv4_and_ipv6() {
        let ordered = order_tcp_connect_addrs(
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
    fn udp_dns_cache_returns_fresh_entries_and_expires() {
        let cache = UdpDnsCache::new(std::time::Duration::from_millis(5));
        let resolved = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53));

        cache.store("dns.google", 53, false, resolved);
        assert_eq!(cache.lookup("dns.google", 53, false), Some(resolved));

        std::thread::sleep(std::time::Duration::from_millis(10));
        assert_eq!(cache.lookup("dns.google", 53, false), None);
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

        let mut client = connect_tcp_addrs(&[blocked_addr, addr], None).await?;
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
        let (read, source) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
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
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let app = build_app(
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp)),
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp)),
            Metrics::new(&config),
            nat_table,
            udp_dns_cache,
            false,
        );
        let server = tokio::spawn(async move { serve_listener(listener, app).await });

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
        let mut socket =
            WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;
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
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let app = build_app(
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp)),
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp)),
            Metrics::new(&config),
            nat_table,
            udp_dns_cache,
            false,
        );
        let server = tokio::spawn(async move { serve_listener(listener, app).await });

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
        let mut socket =
            WebSocketStream::from_raw_socket(upgraded, protocol::Role::Client, None).await;

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
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let app = build_app(
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp)),
            Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp)),
            Metrics::new(&config),
            nat_table,
            udp_dns_cache,
            false,
        );
        let server = tokio::spawn(async move { serve_listener(listener, app).await });

        let bob = users
            .iter()
            .find(|user| user.id() == "bob")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing bob user"))?;
        let (mut socket, _) = connect_async(format!("ws://{listen_addr}/alice-tcp")).await?;
        let mut request = TargetAddr::Socket(upstream_addr).encode()?;
        request.extend_from_slice(b"ping");
        let mut encryptor = AeadStreamEncryptor::new(&bob, None)?;
        let ciphertext = encryptor.encrypt_chunk(&request)?;
        socket.send(WsMessage::Binary(ciphertext.into())).await?;

        let client_outcome =
            tokio::time::timeout(std::time::Duration::from_secs(1), socket.next()).await;
        assert!(
            matches!(
                client_outcome,
                Ok(Some(Ok(WsMessage::Close(_)))) | Ok(Some(Err(_))) | Ok(None)
            ),
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
        let server =
            tokio::spawn(
                async move { serve_ss_tcp_listener(listener, users, metrics, false).await },
            );

        let mut client = TcpStream::connect(listen_addr).await?;
        let mut request = TargetAddr::Socket(upstream_addr).encode()?;
        request.extend_from_slice(b"ping");
        let mut encryptor = AeadStreamEncryptor::new(&user, None)?;
        let ciphertext = encryptor.encrypt_chunk(&request)?;
        client.write_all(&ciphertext).await?;

        let mut encrypted_reply = [0_u8; 256];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read(&mut encrypted_reply),
        )
        .await??;
        assert!(read > 0);

        let mut decryptor = AeadStreamDecryptor::new(Arc::from(vec![user].into_boxed_slice()));
        let mut plaintext = Vec::new();
        decryptor.push(&encrypted_reply[..read]);
        decryptor.pull_plaintext(&mut plaintext)?;
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
        let tcp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Tcp));
        let udp_routes = Arc::new(build_transport_route_map(users.as_ref(), Transport::Udp));
        let metrics = Metrics::new(&config);
        let nat_table = NatTable::new(std::time::Duration::from_secs(300));
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let server = tokio::spawn(async move {
            serve_h3_server(
                server,
                tcp_routes,
                udp_routes,
                metrics,
                nat_table,
                udp_dns_cache,
                false,
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
        let mut socket =
            H3WebSocketStream::from_raw(h3_stream, H3Role::Client, H3WsConfig::default());
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
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let server = tokio::spawn(async move {
            serve_ss_udp_socket(listener, users, metrics, nat_table, udp_dns_cache, false).await
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
        let udp_dns_cache = UdpDnsCache::new(std::time::Duration::from_secs(30));
        let server = tokio::spawn(async move {
            serve_ss_udp_socket(listener, users, metrics, nat_table, udp_dns_cache, false).await
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
        assert_eq!(
            peers[0], peers[1],
            "NAT socket source port should stay stable across reconnect"
        );

        server.abort();
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
            client_active_ttl_secs: 300,
            udp_nat_idle_timeout_secs: 300,
            ws_path_tcp: "/tcp".into(),
            ws_path_udp: "/udp".into(),
            public_host: None,
            public_scheme: "ws".into(),
            access_key_url_base: None,
            access_key_file_extension: ".yaml".into(),
            print_access_keys: false,
            write_access_keys_dir: None,
            password: None,
            fwmark: None,
            users,
            method: CipherKind::Chacha20IetfPoly1305,
        }
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
}
