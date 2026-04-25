use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use axum::extract::ws::WebSocket;
use bytes::{Bytes, BytesMut};
use sockudo_ws::{Http3 as H3Transport, Stream as H3Stream, WebSocketStream as H3WebSocketStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::mpsc,
};
use tracing::{debug, info, warn};

use crate::{
    metrics::{Metrics, Protocol, TcpUpstreamGuard, Transport},
    outbound::OutboundIpv6,
    protocol::vless::{self, VlessCommand, VlessUser, mask_uuid},
};

use super::{
    super::{
        connect::connect_tcp_target,
        constants::{
            WS_CTRL_CHANNEL_CAPACITY, WS_DATA_CHANNEL_CAPACITY,
            WS_TCP_KEEPALIVE_PING_INTERVAL_SECS,
        },
        dns_cache::DnsCache,
    },
    vless_mux::{self, MuxRouteCtx, MuxServerCtx, MuxState},
    vless_udp::{self, forward_vless_udp_client_frames},
    ws_socket::{AxumWs, H3Ws, WsFrame, WsSocket},
    ws_writer,
};

const MAX_VLESS_HEADER_BUFFER: usize = 512;

pub(in crate::server) struct VlessWsServerCtx {
    pub(in crate::server) metrics: Arc<Metrics>,
    pub(in crate::server) dns_cache: Arc<DnsCache>,
    pub(in crate::server) prefer_ipv4_upstream: bool,
    pub(in crate::server) outbound_ipv6: Option<Arc<OutboundIpv6>>,
}

pub(in crate::server) struct VlessWsRouteCtx {
    pub(in crate::server) users: Arc<[VlessUser]>,
    pub(in crate::server) protocol: Protocol,
    pub(in crate::server) path: Arc<str>,
    pub(in crate::server) candidate_users: Arc<[Arc<str>]>,
}

pub(super) enum UpstreamSession {
    None,
    Tcp(tokio::net::tcp::OwnedWriteHalf),
    Udp(Arc<UdpSocket>),
    Mux(MuxState),
}

pub(super) struct VlessRelayState {
    pub(super) header_buffer: Vec<u8>,
    pub(super) upstream: UpstreamSession,
    pub(super) upstream_to_client: Option<tokio::task::JoinHandle<Result<()>>>,
    pub(super) authenticated_user: Option<VlessUser>,
    upstream_guard: Option<TcpUpstreamGuard>,
    pub(super) udp_client_buffer: BytesMut,
}

pub(super) struct VlessWsOutbound<'a, Msg> {
    pub(super) data_tx: &'a mpsc::Sender<Msg>,
    pub(super) ctrl_tx: &'a mpsc::Sender<Msg>,
    pub(super) make_binary: fn(Bytes) -> Msg,
    pub(super) make_close: fn() -> Msg,
    pub(super) make_try_again_close: fn() -> Msg,
}

impl VlessRelayState {
    fn new() -> Self {
        Self {
            header_buffer: Vec::with_capacity(128),
            upstream: UpstreamSession::None,
            upstream_to_client: None,
            authenticated_user: None,
            upstream_guard: None,
            udp_client_buffer: BytesMut::new(),
        }
    }
}

async fn run_vless_relay<T: WsSocket>(
    socket: T,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
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

    let ping_interval = Duration::from_secs(WS_TCP_KEEPALIVE_PING_INTERVAL_SECS);
    let mut keepalive = tokio::time::interval(ping_interval);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;

    let mut state = VlessRelayState::new();
    let mut client_closed = false;

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
                        if let Err(error) = handle_vless_binary_frame(
                            &mut state,
                            data,
                            server,
                            route,
                            VlessWsOutbound {
                                data_tx: &outbound_data_tx,
                                ctrl_tx: &outbound_ctrl_tx,
                                make_binary: T::binary_msg,
                                make_close: T::close_msg,
                                make_try_again_close: T::close_try_again_msg,
                            },
                        )
                        .await
                        {
                            drop(outbound_ctrl_tx);
                            drop(outbound_data_tx);
                            let _ = writer_task.await;
                            return Err(error);
                        }
                    },
                    WsFrame::Close => {
                        debug!("client closed vless websocket");
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
                let _ = outbound_ctrl_tx.send(T::ping_msg()).await;
            }
        }
    }

    match &mut state.upstream {
        UpstreamSession::Tcp(upstream) => {
            upstream.shutdown().await.ok();
        },
        UpstreamSession::Mux(mux) => {
            mux.shutdown().await;
        },
        UpstreamSession::Udp(_) | UpstreamSession::None => {},
    }

    if client_closed {
        if let Some(task) = state.upstream_to_client.take() {
            task.abort();
        }
    } else if let Some(task) = state.upstream_to_client.take() {
        task.await.context("vless upstream relay task join failed")??;
    }
    if let Some(guard) = state.upstream_guard.take() {
        guard.finish();
    }
    drop(outbound_ctrl_tx);
    drop(outbound_data_tx);
    let _ = writer_task.await;
    Ok(())
}

async fn handle_vless_binary_frame<Msg>(
    state: &mut VlessRelayState,
    data: Bytes,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    outbound: VlessWsOutbound<'_, Msg>,
) -> Result<()>
where
    Msg: Send + 'static,
{
    server
        .metrics
        .record_websocket_binary_frame(Transport::Tcp, route.protocol, "in", data.len());

    match &mut state.upstream {
        UpstreamSession::Tcp(writer) => {
            if let Some(user) = &state.authenticated_user {
                server.metrics.record_tcp_payload_bytes(
                    user.label_arc(),
                    route.protocol,
                    "client_to_target",
                    data.len(),
                );
            }
            writer
                .write_all(&data)
                .await
                .context("failed to write vless websocket data upstream")?;
            return Ok(());
        },
        UpstreamSession::Udp(socket) => {
            let socket = Arc::clone(socket);
            return forward_vless_udp_client_frames(
                &mut state.udp_client_buffer,
                &data,
                socket.as_ref(),
                &server.metrics,
                route.protocol,
                state.authenticated_user.as_ref(),
                &route.path,
            )
            .await;
        },
        UpstreamSession::Mux(mux) => {
            let mux_server = MuxServerCtx {
                dns_cache: Arc::clone(&server.dns_cache),
                prefer_ipv4_upstream: server.prefer_ipv4_upstream,
                outbound_ipv6: server.outbound_ipv6.clone(),
                metrics: Arc::clone(&server.metrics),
            };
            let mux_route = MuxRouteCtx {
                protocol: route.protocol,
                path: Arc::clone(&route.path),
            };
            return vless_mux::handle_client_bytes(
                mux,
                &data,
                &mux_server,
                &mux_route,
                outbound.data_tx,
                outbound.make_binary,
            )
            .await;
        },
        UpstreamSession::None => {},
    }

    state.header_buffer.extend_from_slice(&data);

    let request = match vless::parse_request(&state.header_buffer) {
        Ok(Some(request)) => request,
        Ok(None) => {
            if state.header_buffer.len() > MAX_VLESS_HEADER_BUFFER {
                warn!(path = %route.path, buffered = state.header_buffer.len(), "vless parse error: request header too large");
                return Err(anyhow!("vless request header too large"));
            }
            return Ok(());
        },
        Err(vless::VlessError::UnsupportedCommand(command)) => {
            warn!(path = %route.path, command, "unsupported vless command");
            return Err(anyhow!("unsupported vless command {command:#x}"));
        },
        Err(error) => {
            warn!(path = %route.path, error = %error, "vless parse error");
            return Err(anyhow!(error));
        },
    };

    let user = match vless::find_user(route.users.as_ref(), &request.user_id).cloned() {
        Some(user) => {
            info!(
                user = user.label(),
                path = %route.path,
                command = ?request.command,
                "accepted vless user"
            );
            user
        },
        None => {
            let masked = mask_uuid(&request.user_id);
            warn!(
                user = %masked,
                path = %route.path,
                candidates = ?route.candidate_users,
                "rejected vless user"
            );
            return Err(anyhow!("unknown vless user {masked}"));
        },
    };

    match request.command {
        VlessCommand::Tcp => {
            establish_vless_tcp_upstream(state, request, user, server, route, outbound).await
        },
        VlessCommand::Udp => {
            vless_udp::establish_vless_udp_upstream(state, request, user, server, route, outbound)
                .await
        },
        VlessCommand::Mux => {
            establish_vless_mux_upstream(state, request, user, server, route, outbound).await
        },
    }
}

async fn establish_vless_mux_upstream<Msg>(
    state: &mut VlessRelayState,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    outbound: VlessWsOutbound<'_, Msg>,
) -> Result<()>
where
    Msg: Send + 'static,
{
    info!(user = user.label(), path = %route.path, "vless mux session (xudp)");

    outbound
        .data_tx
        .send((outbound.make_binary)(Bytes::from_static(&[vless::VERSION, 0x00])))
        .await
        .map_err(|error| anyhow!("failed to queue vless mux response header: {error}"))?;

    let mut mux = MuxState::new(user.clone());
    state.authenticated_user = Some(user);

    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    if !leftover.is_empty() {
        let mux_server = MuxServerCtx {
            dns_cache: Arc::clone(&server.dns_cache),
            prefer_ipv4_upstream: server.prefer_ipv4_upstream,
            outbound_ipv6: server.outbound_ipv6.clone(),
            metrics: Arc::clone(&server.metrics),
        };
        let mux_route = MuxRouteCtx {
            protocol: route.protocol,
            path: Arc::clone(&route.path),
        };
        vless_mux::handle_client_bytes(
            &mut mux,
            &leftover,
            &mux_server,
            &mux_route,
            outbound.data_tx,
            outbound.make_binary,
        )
        .await?;
    }

    state.upstream = UpstreamSession::Mux(mux);
    Ok(())
}

async fn establish_vless_tcp_upstream<Msg>(
    state: &mut VlessRelayState,
    request: vless::VlessRequest,
    user: VlessUser,
    server: &VlessWsServerCtx,
    route: &VlessWsRouteCtx,
    outbound: VlessWsOutbound<'_, Msg>,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let target = request.target.clone();
    let target_display = target.display_host_port();
    info!(user = user.label(), path = %route.path, target = %target_display, "vless tcp target");

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
                user.label_arc(),
                route.protocol,
                "success",
                connect_started.elapsed().as_secs_f64(),
            );
            stream
        },
        Err(error) => {
            server.metrics.record_tcp_connect(
                user.label_arc(),
                route.protocol,
                "error",
                connect_started.elapsed().as_secs_f64(),
            );
            warn!(
                user = user.label(),
                protocol = ?route.protocol,
                path = %route.path,
                target = %target_display,
                error = %error,
                "vless upstream connect failed; sending try-again close to client"
            );
            let _ = outbound.ctrl_tx.send((outbound.make_try_again_close)()).await;
            return Err(anyhow::Error::msg(format!("{error:#}"))
                .context(format!("failed to connect to {target_display}"))
                .context("vless upstream tcp connect failed"));
        },
    };

    let (upstream_reader, writer) = stream.into_split();
    outbound
        .data_tx
        .send((outbound.make_binary)(Bytes::from_static(&[vless::VERSION, 0x00])))
        .await
        .map_err(|error| anyhow!("failed to queue vless response header: {error}"))?;

    let tx = outbound.data_tx.clone();
    let metrics = Arc::clone(&server.metrics);
    let user_id = user.label_arc();
    let protocol = route.protocol;
    state.upstream_to_client = Some(tokio::spawn(async move {
        relay_vless_upstream_to_client(
            upstream_reader,
            tx,
            outbound.make_binary,
            outbound.make_close,
            metrics,
            protocol,
            user_id,
        )
        .await
    }));
    server
        .metrics
        .record_tcp_authenticated_session(user.label_arc(), route.protocol);
    state.upstream_guard = Some(
        server
            .metrics
            .open_tcp_upstream_connection(user.label_arc(), route.protocol),
    );
    state.authenticated_user = Some(user);
    state.upstream = UpstreamSession::Tcp(writer);

    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    if !leftover.is_empty()
        && let UpstreamSession::Tcp(writer) = &mut state.upstream
    {
        if let Some(user) = &state.authenticated_user {
            server.metrics.record_tcp_payload_bytes(
                user.label_arc(),
                route.protocol,
                "client_to_target",
                leftover.len(),
            );
        }
        writer
            .write_all(&leftover)
            .await
            .context("failed to write initial vless payload upstream")?;
    }

    Ok(())
}

async fn relay_vless_upstream_to_client<Msg>(
    mut upstream_reader: tokio::net::tcp::OwnedReadHalf,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    make_close: fn() -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user_id: Arc<str>,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let mut buffer = vec![0_u8; 16 * 1024];
    loop {
        let read = upstream_reader
            .read(&mut buffer)
            .await
            .context("failed to read from vless upstream")?;
        if read == 0 {
            break;
        }
        metrics.record_tcp_payload_bytes(Arc::clone(&user_id), protocol, "target_to_client", read);
        tx.send(make_binary(Bytes::copy_from_slice(&buffer[..read])))
            .await
            .map_err(|error| anyhow!("failed to queue vless websocket frame: {error}"))?;
    }
    let _ = tx.send(make_close()).await;
    Ok(())
}

pub(super) async fn handle_vless_connection(
    socket: WebSocket,
    server: Arc<VlessWsServerCtx>,
    route: VlessWsRouteCtx,
) -> Result<()> {
    run_vless_relay::<AxumWs>(AxumWs(socket), &server, &route).await
}

pub(in crate::server) async fn handle_vless_h3_connection(
    socket: H3WebSocketStream<H3Stream<H3Transport>>,
    server: Arc<VlessWsServerCtx>,
    route: VlessWsRouteCtx,
) -> Result<()> {
    run_vless_relay::<H3Ws>(H3Ws(socket), &server, &route).await
}
