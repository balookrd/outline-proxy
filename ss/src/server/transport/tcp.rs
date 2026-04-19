use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use sockudo_ws::{Http3 as H3Transport, Stream as H3Stream, WebSocketStream as H3WebSocketStream};
use tokio::{io::AsyncWriteExt, sync::mpsc};
use tracing::{debug, info};

use crate::{
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE, UserKey,
        diagnose_stream_handshake,
    },
    metrics::{Metrics, Protocol, TcpUpstreamGuard, Transport},
    protocol::parse_target_addr,
};

use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;
use super::super::connect::connect_tcp_target;
use super::super::dns_cache::DnsCache;

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

struct ChannelSink<Msg: Send + 'static> {
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
}

impl<Msg: Send + 'static> super::super::relay::UpstreamSink for ChannelSink<Msg> {
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

#[allow(clippy::too_many_arguments)]
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
    let (mut reader, writer) = socket.split_io();
    let (outbound_data_tx, outbound_data_rx) = mpsc::channel::<T::Msg>(64);
    let (outbound_ctrl_tx, outbound_ctrl_rx) = mpsc::channel::<T::Msg>(8);
    let writer_task = tokio::spawn(ws_writer::run_ws_writer::<T>(
        writer,
        outbound_ctrl_rx,
        outbound_data_rx,
        metrics.clone(),
        Transport::Tcp,
        protocol,
    ));

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

#[allow(clippy::too_many_arguments)]
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
                return Err(error).with_context(|| format!("failed to connect to {target_display}"));
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
            super::super::relay::relay_upstream_to_client(
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_tcp_connection(
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

pub(in crate::server) async fn handle_tcp_h3_connection(
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
