use std::sync::Arc;

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
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket, lookup_host},
    sync::mpsc,
    time::{Duration, timeout},
};
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
    let config = Arc::new(config);
    let users = build_users(&config)?;
    let app = build_app(config.clone(), users.clone());

    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.listen))?;
    info!(
        listen = %config.listen,
        tcp_ws_path = %config.ws_path,
        udp_ws_path = %config.udp_ws_path,
        method = ?config.method,
        users = users.len(),
        "websocket shadowsocks server listening",
    );

    serve_listener(listener, app).await
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
            if is_benign_ws_disconnect(&error) {
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
            if is_benign_ws_disconnect(&error) {
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

async fn serve_listener(listener: TcpListener, app: Router) -> Result<()> {
    axum::serve(listener, app)
        .await
        .context("server exited unexpectedly")
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
    use http_body_util::Empty;
    use hyper::ext::Protocol;
    use hyper_util::{
        client::legacy::Client,
        rt::{TokioExecutor, TokioIo},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol};

    use super::{build_app, build_users, connect_tcp_target, relay_udp_payload, serve_listener};
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

    fn ipv6_unavailable(error: &std::io::Error) -> bool {
        matches!(
            error.kind(),
            std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
        )
    }

    fn sample_config(listen: SocketAddr) -> Config {
        Config {
            listen,
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
}
