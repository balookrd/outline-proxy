use super::auth::{
    ROOT_HTTP_AUTH_MAX_FAILURES, build_not_found_response, build_root_http_auth_challenge_response,
    build_root_http_auth_forbidden_response, build_root_http_auth_success_response,
    parse_failed_root_auth_attempts, parse_root_http_auth_password, password_matches_any_user,
};
use super::connect::{connect_tcp_target, resolve_udp_target};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};

use anyhow::{Context, Result, anyhow};
use axum::{
    body::Body,
    extract::{
        OriginalUri, State,
        ws::{Message, WebSocket, WebSocketUpgrade, rejection::WebSocketUpgradeRejection},
    },
    http::{HeaderMap, Method, StatusCode, Version},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::{
    FutureExt, SinkExt, StreamExt,
    future::BoxFuture,
    stream::{FuturesUnordered, SplitSink, SplitStream},
};
use sockudo_ws::{
    Http3 as H3Transport, Message as H3Message, SplitReader as H3SplitReader,
    SplitWriter as H3SplitWriter, Stream as H3Stream, WebSocketStream as H3WebSocketStream,
};
use tokio::{
    io::AsyncWriteExt,
    sync::mpsc,
};
use tracing::{debug, info, warn};

use crate::{
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE, UserKey,
        decrypt_udp_packet_with_hint, diagnose_stream_handshake, diagnose_udp_packet,
    },
    metrics::{DisconnectReason, Metrics, Protocol, TcpUpstreamGuard, Transport},
    nat::{NatKey, NatTable, ResponseSender, UdpResponseSender},
    protocol::parse_target_addr,
};

use super::constants::{MAX_UDP_PAYLOAD_SIZE, UDP_CACHED_USER_INDEX_EMPTY, UDP_MAX_CONCURRENT_RELAY_TASKS};
use super::dns_cache::DnsCache;
use super::setup::protocol_from_http_version;
use super::state::{AppState, empty_transport_route};

pub(super) async fn tcp_websocket_upgrade(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
) -> Response {
    let ws: WebSocketUpgrade = match ws {
        Ok(ws) => ws,
        Err(_) => return build_not_found_response(Body::empty()),
    };
    let protocol = protocol_from_http_version(version);
    let path: Arc<str> = Arc::from(uri.path());
    let route = state
        .routes
        .tcp
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
    let session = state.services.metrics.open_websocket_session(Transport::Tcp, protocol);
    ws.on_upgrade(move |socket| async move {
        let outcome = match handle_tcp_connection(
            socket,
            Arc::clone(&route.users),
            state.services.metrics.clone(),
            protocol,
            Arc::clone(&path),
            Arc::clone(&route.candidate_users),
            Arc::clone(&state.services.dns_cache),
            state.services.prefer_ipv4_upstream,
        )
        .await
        {
            Ok(()) => DisconnectReason::Normal,
            Err(error) => {
                if is_normal_h3_shutdown(&error) {
                    debug!(?error, "tcp websocket connection closed normally");
                    DisconnectReason::Normal
                } else if is_expected_ws_close(&error) {
                    debug!(?error, "tcp websocket connection closed abruptly");
                    DisconnectReason::ClientDisconnect
                } else {
                    warn!(?error, "tcp websocket connection terminated with error");
                    DisconnectReason::Error
                }
            },
        };
        session.finish(outcome);
    })
}

pub(super) async fn root_http_auth_handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if !state.auth.http_root_auth || !matches!(method, Method::GET | Method::HEAD) {
        return build_not_found_response(Body::empty());
    }

    let failed_attempts = parse_failed_root_auth_attempts(&headers);
    if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
        return build_root_http_auth_forbidden_response(Body::empty());
    }

    match parse_root_http_auth_password(&headers) {
        Some(password) if password_matches_any_user(state.auth.users.as_ref(), &password) => {
            build_root_http_auth_success_response(Body::empty())
        },
        Some(_) => {
            let failed_attempts = failed_attempts.saturating_add(1);
            if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
                build_root_http_auth_forbidden_response(Body::empty())
            } else {
                build_root_http_auth_challenge_response(
                    failed_attempts,
                    state.auth.http_root_realm.as_ref(),
                    Body::empty(),
                )
            }
        },
        None => build_root_http_auth_challenge_response(
            failed_attempts,
            state.auth.http_root_realm.as_ref(),
            Body::empty(),
        ),
    }
}

pub(super) async fn not_found_handler() -> Response {
    build_not_found_response(Body::empty())
}

pub(super) async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics.render_prometheus(),
    )
}

pub(super) async fn udp_websocket_upgrade(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
) -> Response {
    let ws: WebSocketUpgrade = match ws {
        Ok(ws) => ws,
        Err(_) => return build_not_found_response(Body::empty()),
    };
    let ws = ws.write_buffer_size(0);
    let protocol = protocol_from_http_version(version);
    let path: Arc<str> = Arc::from(uri.path());
    let route = state
        .routes
        .udp
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
    let session = state.services.metrics.open_websocket_session(Transport::Udp, protocol);
    let nat_table = Arc::clone(&state.services.nat_table);
    ws.on_upgrade(move |socket| async move {
        let outcome = match handle_udp_connection(
            socket,
            Arc::clone(&route.users),
            state.services.metrics.clone(),
            protocol,
            Arc::clone(&path),
            Arc::clone(&route.candidate_users),
            nat_table,
            Arc::clone(&state.services.dns_cache),
            state.services.prefer_ipv4_upstream,
        )
        .await
        {
            Ok(()) => DisconnectReason::Normal,
            Err(error) => {
                if is_normal_h3_shutdown(&error) {
                    debug!(?error, "udp websocket connection closed normally");
                    DisconnectReason::Normal
                } else if is_expected_ws_close(&error) {
                    debug!(?error, "udp websocket connection closed abruptly");
                    DisconnectReason::ClientDisconnect
                } else {
                    warn!(?error, "udp websocket connection terminated with error");
                    DisconnectReason::Error
                }
            },
        };
        session.finish(outcome);
    })
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

enum WsFrame {
    Binary(Bytes),
    Close,
    Ping(Bytes),
    Pong,
    Text,
}

trait WsSocket: Send + Sized + 'static {
    type Msg: Send + 'static;
    type Reader: Send + 'static;
    type Writer: Send + 'static;

    fn split_io(self) -> (Self::Reader, Self::Writer);
    fn recv(
        reader: &mut Self::Reader,
    ) -> impl Future<Output = Result<Option<Self::Msg>>> + Send + '_;
    fn send(
        writer: &mut Self::Writer,
        msg: Self::Msg,
    ) -> impl Future<Output = Result<()>> + Send + '_;
    fn finish(writer: &mut Self::Writer) -> impl Future<Output = ()> + Send + '_;

    fn classify(msg: Self::Msg) -> WsFrame;
    fn binary_msg(data: Bytes) -> Self::Msg;
    fn close_msg() -> Self::Msg;
    fn pong_msg(payload: Bytes) -> Self::Msg;
    fn binary_len(msg: &Self::Msg) -> Option<usize>;
    fn make_udp_response_sender(
        tx: mpsc::Sender<Self::Msg>,
        protocol: Protocol,
    ) -> UdpResponseSender;
}

struct AxumWs(WebSocket);

impl WsSocket for AxumWs {
    type Msg = Message;
    type Reader = SplitStream<WebSocket>;
    type Writer = SplitSink<WebSocket, Message>;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        let (sink, stream) = self.0.split();
        (stream, sink)
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<Message>> {
        match reader.next().await {
            Some(Ok(m)) => Ok(Some(m)),
            Some(Err(e)) => Err(anyhow::Error::from(e).context("websocket receive failure")),
            None => Ok(None),
        }
    }

    async fn send(writer: &mut Self::Writer, msg: Message) -> Result<()> {
        writer
            .send(msg)
            .await
            .context("failed to write websocket frame")
    }

    async fn finish(_writer: &mut Self::Writer) {}

    fn classify(msg: Message) -> WsFrame {
        match msg {
            Message::Binary(b) => WsFrame::Binary(b),
            Message::Close(_) => WsFrame::Close,
            Message::Ping(p) => WsFrame::Ping(p),
            Message::Pong(_) => WsFrame::Pong,
            Message::Text(_) => WsFrame::Text,
        }
    }

    fn binary_msg(data: Bytes) -> Message {
        Message::Binary(data)
    }
    fn close_msg() -> Message {
        Message::Close(None)
    }
    fn pong_msg(p: Bytes) -> Message {
        Message::Pong(p)
    }
    fn binary_len(m: &Message) -> Option<usize> {
        if let Message::Binary(b) = m {
            Some(b.len())
        } else {
            None
        }
    }
    fn make_udp_response_sender(
        tx: mpsc::Sender<Message>,
        protocol: Protocol,
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(WebSocketResponseSender { tx, protocol }))
    }
}

struct H3Ws(H3WebSocketStream<H3Stream<H3Transport>>);

impl WsSocket for H3Ws {
    type Msg = H3Message;
    type Reader = H3SplitReader<H3Stream<H3Transport>>;
    type Writer = H3SplitWriter<H3Stream<H3Transport>>;

    fn split_io(self) -> (Self::Reader, Self::Writer) {
        self.0.split()
    }

    async fn recv(reader: &mut Self::Reader) -> Result<Option<H3Message>> {
        match reader.next().await {
            Some(Ok(m)) => Ok(Some(m)),
            Some(Err(e)) => Err(anyhow::Error::from(e).context("websocket receive failure")),
            None => Ok(None),
        }
    }

    async fn send(writer: &mut Self::Writer, msg: H3Message) -> Result<()> {
        writer
            .send(msg)
            .await
            .context("failed to write websocket frame")
    }

    async fn finish(writer: &mut Self::Writer) {
        let _ = writer.close(1000, "").await;
    }

    fn classify(msg: H3Message) -> WsFrame {
        match msg {
            H3Message::Binary(b) => WsFrame::Binary(b),
            H3Message::Close(_) => WsFrame::Close,
            H3Message::Ping(p) => WsFrame::Ping(p),
            H3Message::Pong(_) => WsFrame::Pong,
            H3Message::Text(_) => WsFrame::Text,
        }
    }

    fn binary_msg(data: Bytes) -> H3Message {
        H3Message::Binary(data)
    }
    fn close_msg() -> H3Message {
        H3Message::Close(None)
    }
    fn pong_msg(p: Bytes) -> H3Message {
        H3Message::Pong(p)
    }
    fn binary_len(m: &H3Message) -> Option<usize> {
        if let H3Message::Binary(b) = m {
            Some(b.len())
        } else {
            None
        }
    }
    fn make_udp_response_sender(
        tx: mpsc::Sender<H3Message>,
        _protocol: Protocol,
    ) -> UdpResponseSender {
        UdpResponseSender::new(Arc::new(Http3ResponseSender { tx }))
    }
}

async fn run_tcp_relay<T: WsSocket>(
    socket: T,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let (mut reader, mut writer) = socket.split_io();
    let (outbound_data_tx, mut outbound_data_rx) = mpsc::channel::<T::Msg>(64);
    let (outbound_ctrl_tx, mut outbound_ctrl_rx) = mpsc::channel::<T::Msg>(8);
    let writer_metrics = metrics.clone();
    let writer_task = tokio::spawn(async move {
        let result = async {
            let mut ctrl_open = true;
            loop {
                if ctrl_open {
                    tokio::select! {
                        biased;
                        msg = outbound_ctrl_rx.recv() => match msg {
                            Some(m) => T::send(&mut writer, m).await?,
                            None => ctrl_open = false,
                        },
                        msg = outbound_data_rx.recv() => match msg {
                            Some(m) => {
                                if let Some(len) = T::binary_len(&m) {
                                    writer_metrics.record_websocket_binary_frame(
                                        Transport::Tcp, protocol, "out", len,
                                    );
                                }
                                T::send(&mut writer, m).await?;
                            }
                            None => break,
                        },
                    }
                } else {
                    let Some(m) = outbound_data_rx.recv().await else {
                        break;
                    };
                    if let Some(len) = T::binary_len(&m) {
                        writer_metrics.record_websocket_binary_frame(
                            Transport::Tcp,
                            protocol,
                            "out",
                            len,
                        );
                    }
                    T::send(&mut writer, m).await?;
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        T::finish(&mut writer).await;
        result
    });

    let mut decryptor = AeadStreamDecryptor::new(users.clone());
    let mut plaintext_buffer = Vec::with_capacity(MAX_CHUNK_SIZE);
    let mut state = TcpRelayState::new();
    let mut client_closed = false;

    while let Some(msg) = T::recv(&mut reader).await? {
        match T::classify(msg) {
            WsFrame::Binary(data) => {
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
                    dns_cache.as_ref(),
                    prefer_ipv4_upstream,
                    T::binary_msg,
                    T::close_msg,
                )
                .await?;
            },
            WsFrame::Close => {
                debug!("client closed tcp websocket");
                client_closed = true;
                break;
            },
            WsFrame::Ping(payload) => {
                outbound_ctrl_tx
                    .send(T::pong_msg(payload))
                    .await
                    .map_err(|_| anyhow!("failed to queue websocket pong"))?;
            },
            WsFrame::Pong => {},
            WsFrame::Text => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    if let Some(mut upstream) = state.upstream_writer.take() {
        upstream.shutdown().await.ok();
    }

    if client_closed {
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
            task.await.context("tcp upstream relay task join failed")??;
        }
        if let Some(guard) = state.upstream_guard.take() {
            guard.finish();
        }
        drop(outbound_ctrl_tx);
        drop(outbound_data_tx);
        writer_task.await.context("websocket writer task join failed")??;
    }
    Ok(())
}

struct WebSocketResponseSender {
    tx: mpsc::Sender<Message>,
    protocol: Protocol,
}

impl ResponseSender for WebSocketResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(Message::Binary(data)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        self.protocol
    }
}

struct Http3ResponseSender {
    tx: mpsc::Sender<H3Message>,
}

impl ResponseSender for Http3ResponseSender {
    fn send_bytes(&self, data: Bytes) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.tx.send(H3Message::Binary(data)).await.is_ok() })
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http3
    }
}

struct ChannelSink<Msg: Send + 'static> {
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
}

impl<Msg: Send + 'static> super::relay::UpstreamSink for ChannelSink<Msg> {
    async fn send_ciphertext(&mut self, ciphertext: Bytes) -> Result<()> {
        self.tx
            .send((self.make_binary)(ciphertext))
            .await
            .map_err(|error| anyhow!("failed to queue encrypted websocket frame: {error}"))
    }

    async fn close(&mut self) {
        let _ = self.tx.send((self.make_close)()).await;
    }
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
    candidate_users: &[Arc<str>],
    dns_cache: &DnsCache,
    prefer_ipv4_upstream: bool,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    metrics.record_websocket_binary_frame(Transport::Tcp, protocol, "in", data.len());
    decryptor.feed_ciphertext(&data);
    match decryptor.drain_plaintext(plaintext_buffer) {
        Ok(()) => {},
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
        },
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
        let stream = match connect_tcp_target(dns_cache, &target, user.fwmark(), prefer_ipv4_upstream).await {
            Ok(stream) => {
                metrics.record_tcp_connect(
                    Arc::clone(&user_id),
                    protocol,
                    "success",
                    connect_started.elapsed().as_secs_f64(),
                );
                stream
            },
            Err(error) => {
                metrics.record_tcp_connect(
                    Arc::clone(&user_id),
                    protocol,
                    "error",
                    connect_started.elapsed().as_secs_f64(),
                );
                return Err(error)
                    .with_context(|| format!("failed to connect to {target_display}"));
            },
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
            super::relay::relay_upstream_to_client(
                upstream_reader,
                ChannelSink { tx, make_binary, make_close },
                &mut encryptor,
                relay_metrics,
                protocol,
                relay_user_id,
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
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    udp_session_recorded: Arc<AtomicBool>,
    cached_user_index: Arc<AtomicUsize>,
    dns_cache: Arc<DnsCache>,
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
        },
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
        resolve_udp_target(dns_cache.as_ref(), &target, prefer_ipv4_upstream).await?;
    info!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        path = %path,
        target = %target_display,
        resolved = %resolved,
        "udp datagram relay"
    );

    let nat_key = NatKey {
        user_id: Arc::clone(&user_id),
        fwmark: packet.user.fwmark(),
        target: resolved,
    };
    let entry = nat_table
        .get_or_create(nat_key, &packet.user, packet.session.clone(), Arc::clone(&metrics))
        .await
        .with_context(|| format!("failed to create NAT entry for {resolved}"))?;

    entry
        .register_session(
            make_response_sender(outbound_tx, protocol),
            packet.session.clone(),
        )
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
    metrics.record_udp_request(user_id, protocol, "success", started_at.elapsed().as_secs_f64());

    Ok(())
}

async fn handle_tcp_connection(
    socket: WebSocket,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    run_tcp_relay::<AxumWs>(
        AxumWs(socket),
        users,
        metrics,
        protocol,
        path,
        candidate_users,
        dns_cache,
        prefer_ipv4_upstream,
    )
    .await
}

async fn run_udp_relay<T: WsSocket>(
    socket: T,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    let (mut reader, mut writer) = socket.split_io();
    let (outbound_data_tx, mut outbound_data_rx) = mpsc::channel::<T::Msg>(64);
    let (outbound_ctrl_tx, mut outbound_ctrl_rx) = mpsc::channel::<T::Msg>(8);
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
                            Some(m) => T::send(&mut writer, m).await?,
                            None => ctrl_open = false,
                        },
                        msg = outbound_data_rx.recv() => match msg {
                            Some(m) => {
                                if let Some(len) = T::binary_len(&m) {
                                    writer_metrics.record_websocket_binary_frame(
                                        Transport::Udp, protocol, "out", len,
                                    );
                                }
                                T::send(&mut writer, m).await?;
                            }
                            None => break,
                        },
                    }
                } else {
                    let Some(m) = outbound_data_rx.recv().await else {
                        break;
                    };
                    if let Some(len) = T::binary_len(&m) {
                        writer_metrics.record_websocket_binary_frame(
                            Transport::Udp,
                            protocol,
                            "out",
                            len,
                        );
                    }
                    T::send(&mut writer, m).await?;
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        T::finish(&mut writer).await;
        result
    });

    let mut loop_result = Ok(());
    loop {
        tokio::select! {
            Some(()) = in_flight.next(), if !in_flight.is_empty() => {}
            msg = T::recv(&mut reader) => {
                let frame = match msg {
                    Ok(Some(m)) => m,
                    Ok(None) => break,
                    Err(error) => {
                        loop_result = Err(error);
                        break;
                    }
                };
                match T::classify(frame) {
                    WsFrame::Binary(data) => {
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
                        let dns_cache = Arc::clone(&dns_cache);
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
                                dns_cache,
                                prefer_ipv4_upstream,
                                T::make_udp_response_sender,
                            )
                            .await
                            {
                                warn!(?error, "udp datagram relay failed");
                            }
                        }.boxed());
                    }
                    WsFrame::Close => {
                        debug!("client closed udp websocket");
                        break;
                    }
                    WsFrame::Ping(payload) => {
                        if outbound_ctrl_tx
                            .send(T::pong_msg(payload))
                            .await
                            .is_err()
                        {
                            loop_result = Err(anyhow!("failed to queue websocket pong"));
                            break;
                        }
                    }
                    WsFrame::Pong => {}
                    WsFrame::Text => {
                        loop_result = Err(anyhow!("text websocket frames are not supported"));
                        break;
                    }
                }
            }
        }
    }

    while in_flight.next().await.is_some() {}
    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    writer_task.await.context("websocket writer task join failed")??;
    loop_result
}

async fn handle_udp_connection(
    socket: WebSocket,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    run_udp_relay::<AxumWs>(
        AxumWs(socket),
        users,
        metrics,
        protocol,
        path,
        candidate_users,
        nat_table,
        dns_cache,
        prefer_ipv4_upstream,
    )
    .await
}

pub(super) async fn handle_tcp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    run_tcp_relay::<H3Ws>(
        H3Ws(socket),
        users,
        metrics,
        Protocol::Http3,
        path,
        candidate_users,
        dns_cache,
        prefer_ipv4_upstream,
    )
    .await
}

pub(super) async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    path: Arc<str>,
    candidate_users: Arc<[Arc<str>]>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
    prefer_ipv4_upstream: bool,
) -> Result<()> {
    run_udp_relay::<H3Ws>(
        H3Ws(socket),
        users,
        metrics,
        Protocol::Http3,
        path,
        candidate_users,
        nat_table,
        dns_cache,
        prefer_ipv4_upstream,
    )
    .await
}

pub(super) fn is_expected_ws_close(error: &anyhow::Error) -> bool {
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

pub(super) fn is_normal_h3_shutdown(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("ApplicationClose: H3_NO_ERROR")
            || message.contains("Remote error: ApplicationClose: H3_NO_ERROR")
            || message.contains("ApplicationClose: 0x0")
    })
}
