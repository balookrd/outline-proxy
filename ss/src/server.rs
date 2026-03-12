use std::{fs, path::Path, sync::{Arc, OnceLock}};

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Method, Version},
    routing::any,
};
use futures_util::{SinkExt, StreamExt};
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
    time::{Duration, timeout},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::{
    config::Config,
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, MAX_CHUNK_SIZE, UserKey, decrypt_udp_packet,
        encrypt_udp_packet,
    },
    protocol::{TargetAddr, parse_target_addr},
};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    users: Arc<[UserKey]>,
}

pub async fn run(config: Config) -> Result<()> {
    ensure_rustls_provider_installed();
    let config = Arc::new(config);
    let users = build_users(&config)?;
    let app = build_app(config.clone(), users.clone());
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.listen))?;
    let h3_server = if config.h3_enabled() {
        Some(build_h3_server(config.as_ref()).await?)
    } else {
        None
    };
    info!(
        listen = %config.listen,
        tcp_tls = config.tcp_tls_enabled(),
        h3_listen = ?config.effective_h3_listen(),
        tcp_ws_path = %config.ws_path,
        udp_ws_path = %config.udp_ws_path,
        method = ?config.method,
        users = users.len(),
        "websocket shadowsocks server listening",
    );

    if let Some(h3_server) = h3_server {
        tokio::try_join!(
            serve_tcp_listener(listener, app, config.as_ref()),
            serve_h3_server(h3_server, config.clone(), users.clone())
        )?;
        Ok(())
    } else {
        serve_tcp_listener(listener, app, config.as_ref()).await
    }
}

async fn tcp_websocket_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    method: Method,
    version: Version,
) -> axum::response::Response {
    info!(?method, ?version, path = %state.config.ws_path, "incoming tcp websocket upgrade");
    ws.on_upgrade(move |socket| async move {
        if let Err(error) =
            handle_tcp_connection(socket, state.config.clone(), state.users.clone()).await
        {
            if is_normal_h3_shutdown(&error) {
                debug!(?error, "tcp websocket connection closed normally");
            } else if is_benign_ws_disconnect(&error) {
                debug!(?error, "tcp websocket connection closed abruptly");
            } else {
                warn!(?error, "tcp websocket connection terminated with error");
            }
        }
    })
}

async fn udp_websocket_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    method: Method,
    version: Version,
) -> axum::response::Response {
    info!(?method, ?version, path = %state.config.udp_ws_path, "incoming udp websocket upgrade");
    ws.on_upgrade(move |socket| async move {
        if let Err(error) =
            handle_udp_connection(socket, state.config.clone(), state.users.clone()).await
        {
            if is_normal_h3_shutdown(&error) {
                debug!(?error, "udp websocket connection closed normally");
            } else if is_benign_ws_disconnect(&error) {
                debug!(?error, "udp websocket connection closed abruptly");
            } else {
                warn!(?error, "udp websocket connection terminated with error");
            }
        }
    })
}

async fn handle_tcp_connection(
    socket: WebSocket,
    config: Arc<Config>,
    users: Arc<[UserKey]>,
) -> Result<()> {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Message>(64);
    let writer_task = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            ws_sender
                .send(message)
                .await
                .context("failed to write websocket frame")?;
        }
        Ok::<(), anyhow::Error>(())
    });
    let mut decryptor = AeadStreamDecryptor::new(config.method, users);
    let mut plaintext_buffer = Vec::new();
    let mut upstream_writer = None;
    let mut upstream_to_client = None;

    while let Some(message) = ws_receiver.next().await {
        match message.context("websocket receive failure")? {
            Message::Binary(data) => {
                decryptor.push(&data);
                let plaintext_chunks = decryptor.pull_plaintext()?;
                for chunk in plaintext_chunks {
                    plaintext_buffer.extend_from_slice(&chunk);
                }

                if upstream_writer.is_none() {
                    let Some((target, consumed)) = parse_target_addr(&plaintext_buffer)? else {
                        continue;
                    };
                    let Some(user) = decryptor.user().cloned() else {
                        continue;
                    };
                    let target_display = target.display_host_port();
                    let stream = connect_tcp_target(&target, user.fwmark())
                        .await
                        .with_context(|| format!("failed to connect to {target_display}"))?;
                    info!(
                        user = user.id(),
                        fwmark = ?user.fwmark(),
                        target = %target_display,
                        "tcp upstream connected"
                    );

                    let (upstream_reader, writer) = stream.into_split();
                    let mut encryptor = AeadStreamEncryptor::new(config.method, &user)?;
                    let tx = outbound_tx.clone();
                    upstream_to_client = Some(tokio::spawn(async move {
                        relay_upstream_to_client(upstream_reader, tx, &mut encryptor).await
                    }));
                    upstream_writer = Some(writer);
                    plaintext_buffer.drain(..consumed);
                }

                if let Some(writer) = &mut upstream_writer {
                    if !plaintext_buffer.is_empty() {
                        writer
                            .write_all(&plaintext_buffer)
                            .await
                            .context("failed to write decrypted data upstream")?;
                        plaintext_buffer.clear();
                    }
                }
            }
            Message::Close(_) => {
                debug!("client closed tcp websocket");
                break;
            }
            Message::Ping(payload) => {
                outbound_tx
                    .send(Message::Pong(payload))
                    .await
                    .context("failed to queue websocket pong")?;
            }
            Message::Pong(_) => {}
            Message::Text(_) => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    if let Some(mut writer) = upstream_writer {
        writer.shutdown().await.ok();
    }

    if let Some(task) = upstream_to_client {
        task.await
            .context("tcp upstream relay task join failed")??;
    }

    drop(outbound_tx);
    writer_task
        .await
        .context("websocket writer task join failed")??;
    Ok(())
}

async fn handle_udp_connection(
    socket: WebSocket,
    config: Arc<Config>,
    users: Arc<[UserKey]>,
) -> Result<()> {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Message>(64);
    let writer_task = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            ws_sender
                .send(message)
                .await
                .context("failed to write websocket frame")?;
        }
        Ok::<(), anyhow::Error>(())
    });

    while let Some(message) = ws_receiver.next().await {
        match message.context("websocket receive failure")? {
            Message::Binary(data) => {
                let tx = outbound_tx.clone();
                let users = users.clone();
                let method = config.method;
                tokio::spawn(async move {
                    if let Err(error) = handle_udp_datagram(method, users, data.to_vec(), tx).await
                    {
                        warn!(?error, "udp datagram relay failed");
                    }
                });
            }
            Message::Close(_) => {
                debug!("client closed udp websocket");
                break;
            }
            Message::Ping(payload) => {
                outbound_tx
                    .send(Message::Pong(payload))
                    .await
                    .context("failed to queue websocket pong")?;
            }
            Message::Pong(_) => {}
            Message::Text(_) => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    drop(outbound_tx);
    writer_task
        .await
        .context("websocket writer task join failed")??;
    Ok(())
}

async fn handle_tcp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    config: Arc<Config>,
    users: Arc<[UserKey]>,
) -> Result<()> {
    let (mut ws_reader, mut ws_writer) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<H3Message>(64);
    let writer_task = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            ws_writer
                .send(message)
                .await
                .context("failed to write websocket frame")?;
        }
        let _ = ws_writer.close(1000, "").await;
        Ok::<(), anyhow::Error>(())
    });
    let mut decryptor = AeadStreamDecryptor::new(config.method, users);
    let mut plaintext_buffer = Vec::new();
    let mut upstream_writer = None;
    let mut upstream_to_client = None;

    while let Some(message) = ws_reader.next().await {
        match message.context("websocket receive failure")? {
            H3Message::Binary(data) => {
                decryptor.push(&data);
                let plaintext_chunks = decryptor.pull_plaintext()?;
                for chunk in plaintext_chunks {
                    plaintext_buffer.extend_from_slice(&chunk);
                }

                if upstream_writer.is_none() {
                    let Some((target, consumed)) = parse_target_addr(&plaintext_buffer)? else {
                        continue;
                    };
                    let Some(user) = decryptor.user().cloned() else {
                        continue;
                    };
                    let target_display = target.display_host_port();
                    let stream = connect_tcp_target(&target, user.fwmark())
                        .await
                        .with_context(|| format!("failed to connect to {target_display}"))?;
                    info!(
                        user = user.id(),
                        fwmark = ?user.fwmark(),
                        target = %target_display,
                        "tcp upstream connected"
                    );

                    let (upstream_reader, writer) = stream.into_split();
                    let mut encryptor = AeadStreamEncryptor::new(config.method, &user)?;
                    let tx = outbound_tx.clone();
                    upstream_to_client = Some(tokio::spawn(async move {
                        relay_upstream_to_h3_client(upstream_reader, tx, &mut encryptor).await
                    }));
                    upstream_writer = Some(writer);
                    plaintext_buffer.drain(..consumed);
                }

                if let Some(writer) = &mut upstream_writer {
                    if !plaintext_buffer.is_empty() {
                        writer
                            .write_all(&plaintext_buffer)
                            .await
                            .context("failed to write decrypted data upstream")?;
                        plaintext_buffer.clear();
                    }
                }
            }
            H3Message::Close(_) => {
                debug!("client closed tcp websocket");
                break;
            }
            H3Message::Ping(_) | H3Message::Pong(_) => {}
            H3Message::Text(_) => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    if let Some(mut writer) = upstream_writer {
        writer.shutdown().await.ok();
    }

    if let Some(task) = upstream_to_client {
        task.await
            .context("tcp upstream relay task join failed")??;
    }

    drop(outbound_tx);
    writer_task
        .await
        .context("websocket writer task join failed")??;
    Ok(())
}

async fn handle_udp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    config: Arc<Config>,
    users: Arc<[UserKey]>,
) -> Result<()> {
    let (mut ws_reader, mut ws_writer) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<H3Message>(64);
    let writer_task = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            ws_writer
                .send(message)
                .await
                .context("failed to write websocket frame")?;
        }
        let _ = ws_writer.close(1000, "").await;
        Ok::<(), anyhow::Error>(())
    });

    while let Some(message) = ws_reader.next().await {
        match message.context("websocket receive failure")? {
            H3Message::Binary(data) => {
                let tx = outbound_tx.clone();
                let users = users.clone();
                let method = config.method;
                tokio::spawn(async move {
                    if let Err(error) = handle_udp_h3_datagram(method, users, data.to_vec(), tx).await
                    {
                        warn!(?error, "udp datagram relay failed");
                    }
                });
            }
            H3Message::Close(_) => {
                debug!("client closed udp websocket");
                break;
            }
            H3Message::Ping(_) | H3Message::Pong(_) => {}
            H3Message::Text(_) => return Err(anyhow!("text websocket frames are not supported")),
        }
    }

    drop(outbound_tx);
    writer_task
        .await
        .context("websocket writer task join failed")??;
    Ok(())
}

async fn relay_upstream_to_client(
    mut upstream_reader: tokio::net::tcp::OwnedReadHalf,
    outbound_tx: mpsc::Sender<Message>,
    encryptor: &mut AeadStreamEncryptor,
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

        let ciphertext = encryptor.encrypt_chunk(&buffer[..read])?;
        outbound_tx
            .send(Message::Binary(ciphertext.into()))
            .await
            .context("failed to queue encrypted websocket frame")?;
    }

    outbound_tx.send(Message::Close(None)).await.ok();
    Ok(())
}

async fn relay_upstream_to_h3_client(
    mut upstream_reader: tokio::net::tcp::OwnedReadHalf,
    outbound_tx: mpsc::Sender<H3Message>,
    encryptor: &mut AeadStreamEncryptor,
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

        let ciphertext = encryptor.encrypt_chunk(&buffer[..read])?;
        outbound_tx
            .send(H3Message::Binary(ciphertext.into()))
            .await
            .context("failed to queue encrypted websocket frame")?;
    }

    outbound_tx.send(H3Message::Close(None)).await.ok();
    Ok(())
}

async fn handle_udp_datagram(
    method: crate::config::CipherKind,
    users: Arc<[UserKey]>,
    data: Vec<u8>,
    outbound_tx: mpsc::Sender<Message>,
) -> Result<()> {
    let packet = decrypt_udp_packet(method, users.as_ref(), &data)?;
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.display_host_port();
    info!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        target = %target_display,
        "udp datagram relay"
    );

    let responses = relay_udp_payload(&target, payload, packet.user.fwmark()).await?;
    for (source, response_payload) in responses {
        let mut plaintext = TargetAddr::Socket(source).encode()?;
        plaintext.extend_from_slice(&response_payload);
        let ciphertext = encrypt_udp_packet(method, &packet.user, &plaintext)?;
        outbound_tx
            .send(Message::Binary(ciphertext.into()))
            .await
            .context("failed to queue udp response")?;
    }

    Ok(())
}

async fn handle_udp_h3_datagram(
    method: crate::config::CipherKind,
    users: Arc<[UserKey]>,
    data: Vec<u8>,
    outbound_tx: mpsc::Sender<H3Message>,
) -> Result<()> {
    let packet = decrypt_udp_packet(method, users.as_ref(), &data)?;
    let Some((target, consumed)) = parse_target_addr(&packet.payload)? else {
        return Err(anyhow!("udp packet is missing a complete target address"));
    };
    let payload = &packet.payload[consumed..];
    let target_display = target.display_host_port();
    info!(
        user = packet.user.id(),
        fwmark = ?packet.user.fwmark(),
        target = %target_display,
        "udp datagram relay"
    );

    let responses = relay_udp_payload(&target, payload, packet.user.fwmark()).await?;
    for (source, response_payload) in responses {
        let mut plaintext = TargetAddr::Socket(source).encode()?;
        plaintext.extend_from_slice(&response_payload);
        let ciphertext = encrypt_udp_packet(method, &packet.user, &plaintext)?;
        outbound_tx
            .send(H3Message::Binary(ciphertext.into()))
            .await
            .context("failed to queue udp response")?;
    }

    Ok(())
}

async fn relay_udp_payload(
    target: &TargetAddr,
    payload: &[u8],
    fwmark: Option<u32>,
) -> Result<Vec<(std::net::SocketAddr, Vec<u8>)>> {
    let resolved = resolve_target(target).await?;
    let bind_addr = if resolved.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind udp socket for {resolved}"))?;
    apply_fwmark_if_needed(&socket, fwmark)
        .with_context(|| format!("failed to apply fwmark {fwmark:?} to udp socket"))?;
    socket
        .send_to(payload, resolved)
        .await
        .with_context(|| format!("failed to send udp datagram to {resolved}"))?;

    let mut buffer = vec![0_u8; 65_535];
    let mut responses = Vec::new();

    let first = timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await;
    match first {
        Ok(Ok((read, source))) => responses.push((source, buffer[..read].to_vec())),
        Ok(Err(error)) => return Err(error).context("failed to receive udp response"),
        Err(_) => return Ok(responses),
    }

    loop {
        match timeout(Duration::from_millis(30), socket.recv_from(&mut buffer)).await {
            Ok(Ok((read, source))) => responses.push((source, buffer[..read].to_vec())),
            Ok(Err(error)) => return Err(error).context("failed to receive udp response"),
            Err(_) => break,
        }
    }

    Ok(responses)
}

async fn resolve_target(target: &TargetAddr) -> Result<std::net::SocketAddr> {
    match target {
        TargetAddr::Socket(addr) => Ok(*addr),
        TargetAddr::Domain(host, port) => lookup_host((host.as_str(), *port))
            .await
            .with_context(|| format!("dns lookup failed for {host}:{port}"))?
            .next()
            .ok_or_else(|| anyhow!("dns lookup returned no records for {host}:{port}")),
    }
}

async fn connect_tcp_target(target: &TargetAddr, fwmark: Option<u32>) -> Result<TcpStream> {
    let resolved = resolve_target(target).await?;
    let socket = if resolved.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .with_context(|| format!("failed to create tcp socket for {resolved}"))?;

    apply_fwmark_if_needed(&socket, fwmark)
        .with_context(|| format!("failed to apply fwmark {fwmark:?} to tcp socket"))?;

    socket
        .connect(resolved)
        .await
        .with_context(|| format!("tcp connect failed for {resolved}"))
}

#[cfg(unix)]
fn apply_fwmark_if_needed<T>(socket: &T, fwmark: Option<u32>) -> std::io::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    if let Some(fwmark) = fwmark {
        apply_fwmark(socket, fwmark)
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn apply_fwmark_if_needed<T>(_socket: &T, fwmark: Option<u32>) -> std::io::Result<()> {
    if fwmark.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fwmark is only supported on Unix/Linux",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_fwmark<T>(socket: &T, fwmark: u32) -> std::io::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    let value: libc::c_uint = fwmark;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn apply_fwmark<T>(_socket: &T, _fwmark: u32) -> std::io::Result<()>
where
    T: std::os::fd::AsRawFd,
{
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "fwmark is only supported on Linux",
    ))
}

fn is_benign_ws_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("Connection reset without closing handshake")
            || message.contains("Connection reset by peer")
            || message.contains("Broken pipe")
            || message.contains("connection closed before message completed")
            || message.contains("Sending after closing is not allowed")
            || message.contains("ApplicationClose: H3_NO_ERROR")
            || message.contains("Remote error: ApplicationClose: H3_NO_ERROR")
    })
}

fn is_normal_h3_shutdown(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("ApplicationClose: H3_NO_ERROR")
            || message.contains("Remote error: ApplicationClose: H3_NO_ERROR")
    })
}

fn build_users(config: &Config) -> Result<Arc<[UserKey]>> {
    Ok(Arc::from(
        config
            .user_entries()?
            .into_iter()
            .map(|entry| UserKey::new(config.method, entry.id, &entry.password, entry.fwmark))
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice(),
    ))
}

fn build_app(config: Arc<Config>, users: Arc<[UserKey]>) -> Router {
    let tcp_route: &'static str = Box::leak(config.ws_path.clone().into_boxed_str());
    let udp_route: &'static str = Box::leak(config.udp_ws_path.clone().into_boxed_str());

    Router::new()
        // HTTP/1.1 WebSocket uses GET, while RFC 8441 over HTTP/2 uses CONNECT.
        .route(tcp_route, any(tcp_websocket_upgrade))
        .route(udp_route, any(udp_websocket_upgrade))
        .with_state(AppState { config, users })
}

async fn build_h3_server(config: &Config) -> Result<H3WebSocketServer<H3Transport>> {
    let listen = config
        .effective_h3_listen()
        .ok_or_else(|| anyhow!("h3 server requested without tls configuration"))?;
    let tls_config = load_h3_tls_config(config)?;
    let ws_config = H3WebSocketConfig::default();
    H3WebSocketServer::<H3Transport>::bind(listen, tls_config, ws_config)
        .await
        .context("failed to bind HTTP/3 WebSocket server")
}

async fn serve_tcp_listener(listener: TcpListener, app: Router, config: &Config) -> Result<()> {
    if config.tcp_tls_enabled() {
        let acceptor = build_tcp_tls_acceptor(config)?;
        serve_tls_listener(listener, app, acceptor).await
    } else {
        serve_listener(listener, app).await
    }
}

async fn serve_h3_server(
    server: H3WebSocketServer<H3Transport>,
    config: Arc<Config>,
    users: Arc<[UserKey]>,
) -> Result<()> {
    let tcp_path = config.ws_path.clone();
    let udp_path = config.udp_ws_path.clone();
    let allowed_tcp = tcp_path.clone();
    let allowed_udp = udp_path.clone();

    server
        .serve_with_filter(
            move |req: &H3ExtendedConnectRequest| req.path == allowed_tcp || req.path == allowed_udp,
            move |socket, req| {
                let config = config.clone();
                let users = users.clone();
                let tcp_path = tcp_path.clone();
                let udp_path = udp_path.clone();
                async move {
                    if req.path == tcp_path {
                        info!(method = "CONNECT", version = "HTTP/3", path = %req.path, "incoming tcp websocket upgrade");
                        if let Err(error) =
                            handle_tcp_h3_connection(socket, config.clone(), users.clone()).await
                        {
                            if is_normal_h3_shutdown(&error) {
                                debug!(?error, "tcp websocket connection closed normally");
                            } else if is_benign_ws_disconnect(&error) {
                                debug!(?error, "tcp websocket connection closed abruptly");
                            } else {
                                warn!(?error, "tcp websocket connection terminated with error");
                            }
                        }
                    } else if req.path == udp_path {
                        info!(method = "CONNECT", version = "HTTP/3", path = %req.path, "incoming udp websocket upgrade");
                        if let Err(error) =
                            handle_udp_h3_connection(socket, config.clone(), users.clone()).await
                        {
                            if is_normal_h3_shutdown(&error) {
                                debug!(?error, "udp websocket connection closed normally");
                            } else if is_benign_ws_disconnect(&error) {
                                debug!(?error, "udp websocket connection closed abruptly");
                            } else {
                                warn!(?error, "udp websocket connection terminated with error");
                            }
                        }
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
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("der")) {
        return Ok(vec![CertificateDer::from(pem)]);
    }

    rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificate chain {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let key = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("der")) {
        return PrivateKeyDer::try_from(key)
            .map_err(|error| anyhow!(error))
            .with_context(|| format!("failed to parse private key {}", path.display()));
    }

    rustls_pemfile::private_key(&mut key.as_slice())
        .with_context(|| format!("failed to parse private key {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

async fn serve_listener(listener: TcpListener, app: Router) -> Result<()> {
    axum::serve(listener, app)
        .await
        .context("server exited unexpectedly")
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
            let builder = HyperBuilder::new(TokioExecutor::new());

            if let Err(error) = builder.serve_connection_with_upgrades(io, service).await {
                if !is_benign_tls_serve_error(error.as_ref()) {
                    warn!(?error, %peer_addr, "tls http server connection terminated with error");
                }
            }
        });
    }
}

fn is_benign_tls_serve_error(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
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
    use futures_util::SinkExt;
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
        net::{TcpListener, UdpSocket},
    };
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol};

    use super::{
        build_app, build_users, connect_tcp_target, relay_udp_payload, serve_h3_server,
        serve_listener,
    };
    use crate::config::{CipherKind, Config, UserEntry};
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
        let mut client = connect_tcp_target(&target, None).await?;
        client.write_all(b"ping").await?;

        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).await?;

        assert_eq!(&reply, b"pong");
        assert_eq!(server.await??, *b"ping");
        Ok(())
    }

    #[tokio::test]
    async fn udp_ipv6_loopback_smoke() -> Result<()> {
        let socket = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
            Ok(socket) => socket,
            Err(error) if ipv6_unavailable(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let addr = socket.local_addr()?;

        let server = tokio::spawn(async move {
            let mut buf = [0_u8; 64];
            let (read, peer) = socket.recv_from(&mut buf).await?;
            socket.send_to(&buf[..read], peer).await?;
            Result::<_, anyhow::Error>::Ok(buf[..read].to_vec())
        });

        let target = TargetAddr::Socket(SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())));
        let responses = relay_udp_payload(&target, b"ping", None).await?;

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].0.ip(), Ipv6Addr::LOCALHOST);
        assert_eq!(responses[0].1, b"ping");
        assert_eq!(server.await??, b"ping");
        Ok(())
    }

    #[tokio::test]
    async fn websocket_rfc8441_http2_connect_smoke() -> Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;

        let config = sample_config(addr);
        let app = build_app(Arc::new(config.clone()), build_users(&config)?);
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
    async fn websocket_rfc9220_http3_connect_smoke() -> Result<()> {
        let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let (tls_config, cert_der) = test_h3_server_tls()?;
        let server = H3WebSocketServer::<H3Transport>::bind(
            server_addr,
            tls_config,
            H3WsConfig::default(),
        )
        .await?;
        let addr = server.local_addr()?;

        let config = sample_config(addr);
        let users = build_users(&config)?;
        let server = tokio::spawn(async move { serve_h3_server(server, Arc::new(config), users).await });

        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        endpoint.set_default_client_config(test_h3_client_config(cert_der)?);

        let connection = endpoint.connect(addr, "localhost")?.await?;
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;
        let driver = tokio::spawn(async move {
            std::future::poll_fn(|cx| driver.poll_close(cx)).await
        });

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

    fn ipv6_unavailable(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
        )
    }

    fn sample_config(listen: SocketAddr) -> Config {
        Config {
            listen,
            tls_cert_path: None,
            tls_key_path: None,
            h3_listen: None,
            h3_cert_path: None,
            h3_key_path: None,
            ws_path: "/tcp".into(),
            udp_ws_path: "/udp".into(),
            public_host: None,
            public_scheme: "ws".into(),
            access_key_url_base: None,
            print_access_keys: false,
            password: None,
            fwmark: None,
            users: vec![UserEntry {
                id: "bob".into(),
                password: "secret-b".into(),
                fwmark: None,
            }],
            method: CipherKind::Chacha20IetfPoly1305,
        }
    }

    fn test_h3_server_tls() -> Result<(rustls::ServerConfig, CertificateDer<'static>)> {
        super::ensure_rustls_provider_installed();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        ));

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
