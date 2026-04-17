use super::connect::{connect_tcp_target, resolve_udp_target};
use super::*;
use axum::{
    body::Body,
    extract::ws::rejection::WebSocketUpgradeRejection,
    http::{HeaderMap, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub(super) const ROOT_HTTP_AUTH_COOKIE_NAME: &str = "outline_ss_root_auth";
pub(super) const ROOT_HTTP_AUTH_MAX_FAILURES: u8 = 3;
pub(super) const ROOT_HTTP_AUTH_COOKIE_TTL_SECS: u32 = 300;

pub(super) async fn tcp_websocket_upgrade(
    ws: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    version: Version,
) -> Response {
    let ws: WebSocketUpgrade = match ws {
        Ok(ws) => ws,
        Err(_) => return not_found_response(),
    };
    let protocol = protocol_from_http_version(version);
    let path: Arc<str> = Arc::from(uri.path());
    let route = state
        .tcp_routes
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming tcp websocket upgrade");
    let session = state.metrics.open_websocket_session(Transport::Tcp, protocol);
    ws.on_upgrade(move |socket| async move {
        let outcome = match handle_tcp_connection(
            socket,
            route.users,
            state.metrics.clone(),
            protocol,
            Arc::clone(&path),
            route.candidate_users,
            state.dns_cache,
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
    if !state.http_root_auth || !matches!(method, Method::GET | Method::HEAD) {
        return not_found_response();
    }

    let failed_attempts = parse_failed_root_auth_attempts(&headers);
    if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
        return root_http_auth_forbidden_response();
    }

    match parse_root_http_auth_password(&headers) {
        Some(password) if password_matches_any_user(state.users.as_ref(), &password) => {
            root_http_auth_success_response()
        },
        Some(_) => {
            let failed_attempts = failed_attempts.saturating_add(1);
            if failed_attempts >= ROOT_HTTP_AUTH_MAX_FAILURES {
                root_http_auth_forbidden_response()
            } else {
                root_http_auth_challenge_response(failed_attempts, state.http_root_realm.as_ref())
            }
        },
        None => root_http_auth_challenge_response(failed_attempts, state.http_root_realm.as_ref()),
    }
}

pub(super) async fn not_found_handler() -> Response {
    not_found_response()
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
        Err(_) => return not_found_response(),
    };
    let ws = ws.write_buffer_size(0);
    let protocol = protocol_from_http_version(version);
    let path: Arc<str> = Arc::from(uri.path());
    let route = state
        .udp_routes
        .get(&*path)
        .cloned()
        .unwrap_or_else(empty_transport_route);
    debug!(?method, ?version, path = %path, candidates = ?route.candidate_users, "incoming udp websocket upgrade");
    let session = state.metrics.open_websocket_session(Transport::Udp, protocol);
    let nat_table = state.nat_table.clone();
    ws.on_upgrade(move |socket| async move {
        let outcome = match handle_udp_connection(
            socket,
            route.users,
            state.metrics.clone(),
            protocol,
            Arc::clone(&path),
            route.candidate_users,
            nat_table,
            state.dns_cache.clone(),
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
            },
        };
        session.finish(outcome);
    })
}

pub(super) fn parse_failed_root_auth_attempts(headers: &HeaderMap) -> u8 {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_cookie(value, ROOT_HTTP_AUTH_COOKIE_NAME))
        .and_then(|value| value.parse::<u8>().ok())
        .map(|attempts| attempts.min(ROOT_HTTP_AUTH_MAX_FAILURES))
        .unwrap_or(0)
}

fn parse_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header.split(';').find_map(|entry| {
        let (cookie_name, cookie_value) = entry.trim().split_once('=')?;
        (cookie_name == name).then_some(cookie_value)
    })
}

pub(super) fn parse_root_http_auth_password(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (_, password) = decoded.split_once(':')?;
    Some(password.to_owned())
}

pub(super) fn password_matches_any_user(users: &[UserKey], password: &str) -> bool {
    users
        .iter()
        .any(|user| matches!(user.matches_password(password), Ok(true)))
}

fn not_found_response() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .expect("failed to build not found response")
}

fn root_http_auth_success_response() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::SET_COOKIE,
            format!("{ROOT_HTTP_AUTH_COOKIE_NAME}=0; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),
        )
        .body(Body::empty())
        .expect("failed to build root auth success response")
}

fn root_http_auth_challenge_response(failed_attempts: u8, realm: &str) -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            header::WWW_AUTHENTICATE,
            format!("Basic realm=\"{}\"", escape_http_auth_realm(realm)),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::SET_COOKIE,
            format!(
                "{ROOT_HTTP_AUTH_COOKIE_NAME}={failed_attempts}; Path=/; Max-Age={ROOT_HTTP_AUTH_COOKIE_TTL_SECS}; HttpOnly; SameSite=Lax"
            ),
        )
        .body(Body::empty())
        .expect("failed to build root auth challenge response")
}

pub(super) fn escape_http_auth_realm(realm: &str) -> String {
    realm.replace('\\', "\\\\").replace('"', "\\\"")
}

fn root_http_auth_forbidden_response() -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::SET_COOKIE,
            format!(
                "{ROOT_HTTP_AUTH_COOKIE_NAME}={ROOT_HTTP_AUTH_MAX_FAILURES}; Path=/; Max-Age={ROOT_HTTP_AUTH_COOKIE_TTL_SECS}; HttpOnly; SameSite=Lax"
            ),
        )
        .body(Body::empty())
        .expect("failed to build root auth forbidden response")
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
    let mut buffer = BytesMut::with_capacity(MAX_CHUNK_SIZE);
    loop {
        buffer.clear();
        buffer.reserve(MAX_CHUNK_SIZE);
        let read = upstream_reader
            .read_buf(&mut buffer)
            .await
            .context("failed to read from upstream")?;
        if read == 0 {
            break;
        }

        metrics.record_tcp_payload_bytes(Arc::clone(&user_id), protocol, "target_to_client", read);
        let ciphertext = encryptor.encrypt_chunk(&buffer)?;
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
    path: Arc<str>,
    candidate_users: Arc<[String]>,
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
        udp_client_session_id: packet.session.client_session_id(),
    };
    let entry = nat_table
        .get_or_create(nat_key, &packet.user, packet.session.clone(), Arc::clone(&metrics))
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
    metrics.record_udp_request(user_id, protocol, "success", started_at.elapsed().as_secs_f64());

    Ok(())
}

async fn handle_tcp_connection(
    socket: WebSocket,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[String]>,
    dns_cache: Arc<DnsCache>,
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
                ws_sender.send(m).await.context("failed to write websocket frame")?;
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
                    dns_cache.as_ref(),
                    prefer_ipv4_upstream,
                    ws_binary_message,
                    ws_close_message,
                )
                .await?;
            },
            Message::Close(_) => {
                debug!("client closed tcp websocket");
                client_closed = true;
                break;
            },
            Message::Ping(payload) => {
                outbound_ctrl_tx
                    .send(ws_pong_message(payload))
                    .await
                    .context("failed to queue websocket pong")?;
            },
            Message::Pong(_) => {},
            Message::Text(_) => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    if let Some(mut writer) = state.upstream_writer.take() {
        writer.shutdown().await.ok();
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

async fn handle_udp_connection(
    socket: WebSocket,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    path: Arc<str>,
    candidate_users: Arc<[String]>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
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
                ws_sender.send(m).await.context("failed to write websocket frame")?;
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
    writer_task.await.context("websocket writer task join failed")??;
    loop_result
}

pub(super) async fn handle_tcp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    path: Arc<str>,
    candidate_users: Arc<[String]>,
    dns_cache: Arc<DnsCache>,
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
                    dns_cache.as_ref(),
                    prefer_ipv4_upstream,
                    h3_binary_message,
                    h3_close_message,
                )
                .await?;
            },
            H3Message::Close(_) => {
                debug!("client closed tcp websocket");
                break;
            },
            H3Message::Ping(payload) => {
                outbound_ctrl_tx
                    .send(h3_pong_message(payload))
                    .await
                    .context("failed to queue websocket pong")?;
            },
            H3Message::Pong(_) => {},
            H3Message::Text(_) => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    if let Some(mut writer) = state.upstream_writer.take() {
        writer.shutdown().await.ok();
    }

    if let Some(task) = state.upstream_to_client.take() {
        task.await.context("tcp upstream relay task join failed")??;
    }

    if let Some(guard) = state.upstream_guard.take() {
        guard.finish();
    }

    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    writer_task.await.context("websocket writer task join failed")??;
    Ok(())
}

pub(super) async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    users: Arc<[UserKey]>,
    metrics: Arc<Metrics>,
    path: Arc<str>,
    candidate_users: Arc<[String]>,
    nat_table: Arc<NatTable>,
    dns_cache: Arc<DnsCache>,
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
                        let dns_cache = Arc::clone(&dns_cache);
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
                                dns_cache,
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
    writer_task.await.context("websocket writer task join failed")??;
    loop_result
}

pub(super) fn is_benign_ws_disconnect(error: &anyhow::Error) -> bool {
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
