use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::Bytes;
use sockudo_ws::{Http3 as H3Transport, Stream as H3Stream, WebSocketStream as H3WebSocketStream};
use std::time::Duration;

use tokio::{io::AsyncWriteExt, sync::mpsc};
use tracing::{debug, info, warn};

/// Typed marker attached to errors that originate from a failed upstream TCP
/// connect inside [`handle_tcp_binary_frame`].  [`run_tcp_relay`] checks for
/// this marker to decide whether to send the client a "try again" close frame
/// (RFC 6455 code 1013) rather than a plain close or a silent drop, so the
/// proxy can retry on the same or a different uplink instead of surfacing the
/// failure to the SOCKS client.
#[derive(Debug)]
struct UpstreamConnectFailed;

impl std::fmt::Display for UpstreamConnectFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("upstream tcp connect failed")
    }
}

impl std::error::Error for UpstreamConnectFailed {}

use crate::{
    crypto::{
        AeadStreamDecryptor, AeadStreamEncryptor, CryptoError, MAX_CHUNK_SIZE, UserKey,
        diagnose_stream_handshake,
    },
    metrics::{Metrics, Protocol, TcpUpstreamGuard, Transport},
    outbound::OutboundIpv6,
    protocol::parse_target_addr,
};

use super::ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket};
use super::ws_writer;
use super::super::connect::connect_tcp_target;
use super::super::constants::{
    WS_CTRL_CHANNEL_CAPACITY, WS_DATA_CHANNEL_CAPACITY, WS_TCP_KEEPALIVE_PING_INTERVAL_SECS,
};
use super::super::dns_cache::DnsCache;

/// Process-wide services shared by every TCP relay session.
pub(in crate::server) struct TcpServerCtx {
    pub(in crate::server) metrics: Arc<Metrics>,
    pub(in crate::server) dns_cache: Arc<DnsCache>,
    pub(in crate::server) prefer_ipv4_upstream: bool,
    pub(in crate::server) outbound_ipv6: Option<Arc<OutboundIpv6>>,
}

/// Per-path state for a single TCP WebSocket session.
pub(in crate::server) struct TcpRouteCtx {
    pub(in crate::server) users: Arc<[UserKey]>,
    pub(in crate::server) protocol: Protocol,
    pub(in crate::server) path: Arc<str>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
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

async fn run_tcp_relay<T: WsSocket>(
    socket: T,
    server: &TcpServerCtx,
    route: &TcpRouteCtx,
) -> Result<()> {
    let (mut reader, writer) = socket.split_io();
    let (outbound_data_tx, outbound_data_rx) = mpsc::channel::<T::Msg>(WS_DATA_CHANNEL_CAPACITY);
    let (outbound_ctrl_tx, outbound_ctrl_rx) = mpsc::channel::<T::Msg>(WS_CTRL_CHANNEL_CAPACITY);
    let writer_task = tokio::spawn(ws_writer::run_ws_writer::<T>(
        writer,
        outbound_ctrl_rx,
        outbound_data_rx,
        server.metrics.clone(),
        Transport::Tcp,
        route.protocol,
    ));

    let mut decryptor = AeadStreamDecryptor::new(route.users.clone());
    let mut plaintext_buffer = Vec::with_capacity(MAX_CHUNK_SIZE);
    let mut state = TcpRelayState::new();
    let mut client_closed = false;

    // Periodic WebSocket Ping sent from server to client.
    //
    // The client's WsReadTransport has a WS_READ_IDLE_TIMEOUT (currently 300 s)
    // that fires when no WS frame has been received.  On a healthy session where
    // the remote target is slow to respond (e.g. a long model-inference step),
    // that timer would fire and abort an otherwise live connection.
    //
    // Sending a Ping every WS_TCP_KEEPALIVE_PING_INTERVAL_SECS seconds keeps
    // the client's timer reset for as long as the session is alive, regardless
    // of how long the remote target takes.  The client's WsReadTransport already
    // handles incoming Pings: it queues a Pong response and loops — every Ping
    // frame also resets the idle timeout.
    let ping_interval = Duration::from_secs(WS_TCP_KEEPALIVE_PING_INTERVAL_SECS);
    let mut keepalive = tokio::time::interval(ping_interval);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await; // skip the first immediate tick

    loop {
        tokio::select! {
            biased;
            result = T::recv(&mut reader) => {
                let msg = match result? {
                    Some(m) => m,
                    None => break,
                };
                match T::classify(msg) {
                    WsFrame::Binary(data) => {
                        if let Err(err) = handle_tcp_binary_frame(
                            &mut state,
                            &mut decryptor,
                            &mut plaintext_buffer,
                            data,
                            &outbound_data_tx,
                            server,
                            route,
                            T::binary_msg,
                            T::close_msg,
                        )
                        .await
                        {
                            // Pick the appropriate WS close code.  When the upstream
                            // TCP connect failed the client has a reasonable chance of
                            // succeeding if it retries (same or different uplink), so
                            // send code 1013 "Try Again Later".  Any other error
                            // (auth failure, protocol error) is terminal — send a
                            // generic close so the client can fail fast.
                            let is_upstream_connect_failure = err
                                .chain()
                                .any(|e| e.downcast_ref::<UpstreamConnectFailed>().is_some());
                            let close_msg = if is_upstream_connect_failure {
                                T::close_try_again_msg()
                            } else {
                                T::close_msg()
                            };
                            let _ = outbound_ctrl_tx.send(close_msg).await;
                            drop(outbound_ctrl_tx);
                            drop(outbound_data_tx);
                            let _ = writer_task.await;
                            return Err(err);
                        }
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
            },
            _ = keepalive.tick() => {
                // Don't fail the session on a Ping send error — the writer task
                // may have already exited if the WS connection closed cleanly on
                // the write side while we were reading.  The next T::recv() call
                // will then return None and we exit normally.
                let _ = outbound_ctrl_tx.send(T::ping_msg()).await;
            }
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

async fn handle_tcp_binary_frame<Msg>(
    state: &mut TcpRelayState,
    decryptor: &mut AeadStreamDecryptor,
    plaintext_buffer: &mut Vec<u8>,
    data: Bytes,
    outbound_data_tx: &mpsc::Sender<Msg>,
    server: &TcpServerCtx,
    route: &TcpRouteCtx,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    server.metrics.record_websocket_binary_frame(Transport::Tcp, route.protocol, "in", data.len());
    decryptor.feed_ciphertext(&data);
    match decryptor.drain_plaintext(plaintext_buffer) {
        Ok(()) => {},
        Err(CryptoError::UnknownUser) => {
            debug!(
                path = %route.path,
                candidates = ?route.candidate_users,
                buffered = decryptor.buffered_data().len(),
                attempts = ?diagnose_stream_handshake(route.users.as_ref(), decryptor.buffered_data()),
                "tcp authentication failed for all path candidates"
            );
            return Err(anyhow!(
                "no configured key matched the incoming data on tcp path {} candidates={:?}",
                route.path,
                route.candidate_users,
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
            path = %route.path,
            "tcp shadowsocks user authenticated"
        );
        let user_id = user.id_arc();
        let target_display = target.display_host_port();
        let connect_started = std::time::Instant::now();
        let stream = match connect_tcp_target(
            server.dns_cache.as_ref(),
            &target,
            user.fwmark(),
            server.prefer_ipv4_upstream,
            server.outbound_ipv6.as_deref(),
        )
        .await
        {
            Ok(stream) => {
                server.metrics.record_tcp_connect(
                    Arc::clone(&user_id),
                    route.protocol,
                    "success",
                    connect_started.elapsed().as_secs_f64(),
                );
                stream
            },
            Err(error) => {
                server.metrics.record_tcp_connect(
                    Arc::clone(&user_id),
                    route.protocol,
                    "error",
                    connect_started.elapsed().as_secs_f64(),
                );
                warn!(
                    user = user.id(),
                    protocol = ?route.protocol,
                    path = %route.path,
                    target = %target_display,
                    error = %error,
                    "websocket tcp upstream connect failed; sending try-again close to client"
                );
                return Err(anyhow!(UpstreamConnectFailed))
                    .with_context(|| format!("failed to connect to {target_display}"))
                    .with_context(|| format!("{error:#}"));
            },
        };
        info!(
            user = user.id(),
            fwmark = ?user.fwmark(),
            path = %route.path,
            target = %target_display,
            "tcp upstream connected"
        );

        let (upstream_reader, writer) = stream.into_split();
        let mut encryptor = AeadStreamEncryptor::new(&user, decryptor.response_context())?;
        let tx = outbound_data_tx.clone();
        let relay_metrics = Arc::clone(&server.metrics);
        let relay_user_id = Arc::clone(&user_id);
        let protocol = route.protocol;
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
        server.metrics.record_tcp_authenticated_session(Arc::clone(&user_id), route.protocol);
        state.upstream_guard = Some(server.metrics.open_tcp_upstream_connection(user_id, route.protocol));
        state.authenticated_user = Some(user);
        state.upstream_writer = Some(writer);
        plaintext_buffer.drain(..consumed);
    }

    if let Some(writer) = &mut state.upstream_writer
        && !plaintext_buffer.is_empty()
    {
        if let Some(user) = &state.authenticated_user {
            server.metrics.record_tcp_payload_bytes(
                user.id_arc(),
                route.protocol,
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

pub(super) async fn handle_tcp_connection(
    socket: WebSocket,
    server: TcpServerCtx,
    route: TcpRouteCtx,
) -> Result<()> {
    run_tcp_relay::<AxumWs>(AxumWs(socket), &server, &route).await
}

pub(in crate::server) async fn handle_tcp_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: TcpServerCtx,
    route: TcpRouteCtx,
) -> Result<()> {
    run_tcp_relay::<H3Ws>(H3Ws(socket), &server, &route).await
}
