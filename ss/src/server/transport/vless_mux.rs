use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UdpSocket, tcp::OwnedWriteHalf},
    sync::mpsc,
};
use tracing::{debug, warn};

use crate::{
    fwmark::apply_fwmark_if_needed,
    metrics::{Metrics, PerUserCounters, Protocol, Transport},
    outbound::OutboundIpv6,
    protocol::{
        TargetAddr,
        vless_mux::{
            self, FrameMeta, MuxError, Network, OPTION_DATA, OPTION_ERROR, ParsedFrame,
            SessionStatus, encode_frame, parse_frame,
        },
        vless::VlessUser,
    },
};

use super::super::{
    abort::AbortOnDrop,
    connect::{connect_tcp_target, resolve_udp_target},
    constants::MAX_UDP_PAYLOAD_SIZE,
    dns_cache::DnsCache,
    nat::bind_nat_udp_socket,
};

/// Maximum number of concurrent mux sub-connections per VLESS session.
/// Matches xray-core's default `Concurrency=8`.
pub(super) const MAX_MUX_SUB_CONNS: usize = 8;

/// Maximum number of bytes we will buffer while waiting for a complete frame.
const MAX_MUX_FRAME_BUFFER: usize = 2 * (vless_mux::MAX_FRAME_DATA_SIZE + 64);

pub(super) struct MuxServerCtx {
    pub dns_cache: Arc<DnsCache>,
    pub prefer_ipv4_upstream: bool,
    pub outbound_ipv6: Option<Arc<OutboundIpv6>>,
    pub metrics: Arc<Metrics>,
}

pub(super) struct MuxRouteCtx {
    pub protocol: Protocol,
    pub path: Arc<str>,
}

pub(super) struct MuxState {
    sub_conns: HashMap<u16, MuxSubConn>,
    buffer: BytesMut,
    user: VlessUser,
    user_counters: Arc<PerUserCounters>,
}

struct MuxSubConn {
    kind: SubConnKind,
    /// Held only for its `Drop`: `AbortOnDrop` cancels the reader task
    /// when the `MuxSubConn` is removed from the map (or the whole
    /// `MuxState` drops). Underscore-prefixed because nothing reads it.
    _reader_task: Option<AbortOnDrop<()>>,
}

enum SubConnKind {
    Tcp(OwnedWriteHalf),
    Udp {
        socket: Arc<UdpSocket>,
        default_target: SocketAddr,
    },
}

impl MuxState {
    pub fn new(user: VlessUser, user_counters: Arc<PerUserCounters>) -> Self {
        Self {
            sub_conns: HashMap::new(),
            buffer: BytesMut::new(),
            user,
            user_counters,
        }
    }

    pub async fn shutdown(&mut self) {
        // Drain shuts down each TCP write half gracefully so the upstream
        // reader sees EOF; the `AbortOnDrop` guard inside each `MuxSubConn`
        // cancels the reader task on drop. The natural `MuxState` drop
        // would do the same on every other exit path (?-return, panic).
        for (_, mut sub) in self.sub_conns.drain() {
            if let SubConnKind::Tcp(mut w) = sub.kind {
                let _ = w.shutdown().await;
            }
            // sub.reader_task drops here → AbortOnDrop fires.
        }
    }
}

pub(super) async fn handle_client_bytes<Msg>(
    state: &mut MuxState,
    data: &[u8],
    server: &MuxServerCtx,
    route: &MuxRouteCtx,
    tx: &mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    state.buffer.extend_from_slice(data);
    loop {
        let (frame_meta, frame_data, consumed) = match parse_frame(&state.buffer) {
            Ok(Some(ParsedFrame { meta, data, consumed })) => {
                let owned = data.map(Bytes::copy_from_slice);
                (meta, owned, consumed)
            },
            Ok(None) => {
                if state.buffer.len() > MAX_MUX_FRAME_BUFFER {
                    return Err(anyhow!(
                        "mux frame buffer overflow: {} bytes",
                        state.buffer.len()
                    ));
                }
                break;
            },
            Err(error) => {
                warn!(path = %route.path, error = %error, "mux frame parse error");
                return Err(anyhow!(error));
            },
        };
        let _ = state.buffer.split_to(consumed);
        dispatch_frame(state, frame_meta, frame_data, server, route, tx, make_binary).await?;
    }
    Ok(())
}

async fn dispatch_frame<Msg>(
    state: &mut MuxState,
    meta: FrameMeta,
    data: Option<Bytes>,
    server: &MuxServerCtx,
    route: &MuxRouteCtx,
    tx: &mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    match meta.status {
        SessionStatus::New => {
            handle_new(state, meta, data, server, route, tx, make_binary).await
        },
        SessionStatus::Keep => {
            handle_keep(state, meta, data, server, route).await
        },
        SessionStatus::End => {
            handle_end(state, meta.session_id).await;
            Ok(())
        },
        SessionStatus::KeepAlive => Ok(()),
    }
}

async fn handle_new<Msg>(
    state: &mut MuxState,
    meta: FrameMeta,
    data: Option<Bytes>,
    server: &MuxServerCtx,
    route: &MuxRouteCtx,
    tx: &mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let session_id = meta.session_id;
    let network = meta.network.ok_or_else(|| anyhow!("mux New frame missing network"))?;
    let target = meta.target.clone().ok_or_else(|| anyhow!("mux New frame missing target"))?;

    if state.sub_conns.contains_key(&session_id) {
        warn!(path = %route.path, session_id, "mux duplicate New for session");
        send_end(tx, make_binary, session_id, true).await?;
        return Ok(());
    }
    if state.sub_conns.len() >= MAX_MUX_SUB_CONNS {
        warn!(path = %route.path, session_id, "mux sub-conn limit reached; rejecting");
        send_end(tx, make_binary, session_id, true).await?;
        return Ok(());
    }

    debug!(
        user = state.user.label(),
        path = %route.path,
        session_id,
        ?network,
        target = %target.display_host_port(),
        global_id = ?meta.global_id,
        "mux New sub-conn"
    );

    match network {
        Network::Tcp => {
            open_tcp_sub(state, session_id, target, data, server, route, tx, make_binary).await
        },
        Network::Udp => {
            open_udp_sub(state, session_id, target, data, server, route, tx, make_binary).await
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_tcp_sub<Msg>(
    state: &mut MuxState,
    session_id: u16,
    target: TargetAddr,
    initial: Option<Bytes>,
    server: &MuxServerCtx,
    route: &MuxRouteCtx,
    tx: &mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let target_display = target.display_host_port();
    let stream = match connect_tcp_target(
        server.dns_cache.as_ref(),
        &target,
        state.user.fwmark(),
        server.prefer_ipv4_upstream,
        server.outbound_ipv6.as_deref(),
    )
    .await
    {
        Ok(s) => s,
        Err(error) => {
            warn!(
                path = %route.path,
                session_id,
                target = %target_display,
                error = %error,
                "mux tcp connect failed"
            );
            send_end(tx, make_binary, session_id, true).await?;
            return Ok(());
        },
    };

    let (reader, mut writer) = stream.into_split();
    if let Some(initial) = initial
        && !initial.is_empty()
    {
        state.user_counters.tcp_in(route.protocol).increment(initial.len() as u64);
        writer
            .write_all(&initial)
            .await
            .context("mux tcp initial write failed")?;
    }

    let tx_task = tx.clone();
    let metrics = Arc::clone(&server.metrics);
    let protocol = route.protocol;
    let user_label = state.user.label_arc();
    let reader_task = tokio::spawn(async move {
        let _ = run_tcp_reader(session_id, reader, tx_task, make_binary, metrics, protocol, user_label).await;
    });

    state.sub_conns.insert(
        session_id,
        MuxSubConn {
            kind: SubConnKind::Tcp(writer),
            _reader_task: Some(AbortOnDrop::new(reader_task)),
        },
    );
    Ok(())
}

async fn run_tcp_reader<Msg>(
    session_id: u16,
    mut reader: tokio::net::tcp::OwnedReadHalf,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user: Arc<str>,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let user_counters = metrics.user_counters(&user);
    let target_to_client = user_counters.tcp_out(protocol);
    let mut buf = vec![0_u8; 16 * 1024];
    let mut frame_buf = BytesMut::with_capacity(16 * 1024 + 16);
    loop {
        let read = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) => {
                debug!(session_id, error = %error, "mux tcp upstream read error");
                break;
            },
        };
        target_to_client.increment(read as u64);
        frame_buf.reserve(read + 16);
        encode_frame(
            &mut frame_buf,
            session_id,
            SessionStatus::Keep,
            OPTION_DATA,
            None,
            None,
            Some(&buf[..read]),
        );
        let frame = frame_buf.split().freeze();
        metrics.record_websocket_binary_frame(Transport::Tcp, protocol, "out", frame.len());
        if tx.send(make_binary(frame)).await.is_err() {
            return Ok(());
        }
    }
    frame_buf.reserve(6);
    encode_frame(&mut frame_buf, session_id, SessionStatus::End, 0, None, None, None);
    let _ = tx.send(make_binary(frame_buf.split().freeze())).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn open_udp_sub<Msg>(
    state: &mut MuxState,
    session_id: u16,
    target: TargetAddr,
    initial: Option<Bytes>,
    server: &MuxServerCtx,
    route: &MuxRouteCtx,
    tx: &mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let default_target = match resolve_udp_target(
        server.dns_cache.as_ref(),
        &target,
        server.prefer_ipv4_upstream,
    )
    .await
    {
        Ok(addr) => addr,
        Err(error) => {
            warn!(
                path = %route.path,
                session_id,
                error = %error,
                "mux udp dns resolution failed"
            );
            send_end(tx, make_binary, session_id, true).await?;
            return Ok(());
        },
    };

    let socket = match bind_unconnected_udp(default_target, state.user.fwmark(), server.outbound_ipv6.as_deref()) {
        Ok(s) => Arc::new(s),
        Err(error) => {
            warn!(
                path = %route.path,
                session_id,
                error = %error,
                "mux udp bind failed"
            );
            send_end(tx, make_binary, session_id, true).await?;
            return Ok(());
        },
    };

    let tx_task = tx.clone();
    let metrics = Arc::clone(&server.metrics);
    let protocol = route.protocol;
    let user_label = state.user.label_arc();
    let reader_socket = Arc::clone(&socket);
    let reader_task = tokio::spawn(async move {
        let _ = run_udp_reader(session_id, reader_socket, tx_task, make_binary, metrics, protocol, user_label).await;
    });

    state.sub_conns.insert(
        session_id,
        MuxSubConn {
            kind: SubConnKind::Udp { socket: Arc::clone(&socket), default_target },
            _reader_task: Some(AbortOnDrop::new(reader_task)),
        },
    );

    if let Some(payload) = initial
        && !payload.is_empty()
    {
        send_udp_payload(&socket, &payload, default_target, &state.user_counters, route.protocol).await;
    }
    Ok(())
}

async fn run_udp_reader<Msg>(
    session_id: u16,
    socket: Arc<UdpSocket>,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user: Arc<str>,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let user_counters = metrics.user_counters(&user);
    let target_to_client = user_counters.udp_out(protocol);
    let mut buf = vec![0_u8; MAX_UDP_PAYLOAD_SIZE];
    let mut frame_buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD_SIZE + 32);
    loop {
        let (read, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(error) => {
                debug!(session_id, error = %error, "mux udp recv error");
                break;
            },
        };
        if read == 0 {
            continue;
        }
        target_to_client.increment(read as u64);
        let src = TargetAddr::Socket(from);
        frame_buf.reserve(read + 32);
        encode_frame(
            &mut frame_buf,
            session_id,
            SessionStatus::Keep,
            OPTION_DATA,
            Some(Network::Udp),
            Some(&src),
            Some(&buf[..read]),
        );
        let frame = frame_buf.split().freeze();
        metrics.record_websocket_binary_frame(Transport::Tcp, protocol, "out", frame.len());
        if tx.send(make_binary(frame)).await.is_err() {
            return Ok(());
        }
    }
    frame_buf.reserve(6);
    encode_frame(&mut frame_buf, session_id, SessionStatus::End, 0, None, None, None);
    let _ = tx.send(make_binary(frame_buf.split().freeze())).await;
    Ok(())
}

async fn handle_keep(
    state: &mut MuxState,
    meta: FrameMeta,
    data: Option<Bytes>,
    server: &MuxServerCtx,
    route: &MuxRouteCtx,
) -> Result<()> {
    let Some(sub) = state.sub_conns.get_mut(&meta.session_id) else {
        debug!(path = %route.path, session_id = meta.session_id, "mux Keep for unknown session");
        return Ok(());
    };

    let Some(payload) = data else {
        return Ok(());
    };

    match &mut sub.kind {
        SubConnKind::Tcp(writer) => {
            state.user_counters.tcp_in(route.protocol).increment(payload.len() as u64);
            if let Err(error) = writer.write_all(&payload).await {
                debug!(session_id = meta.session_id, error = %error, "mux tcp upstream write error");
                finish_sub(state, meta.session_id).await;
            }
        },
        SubConnKind::Udp { socket, default_target } => {
            let dst = match meta.target.as_ref() {
                Some(addr) => match resolve_packet_addr(server.dns_cache.as_ref(), addr, server.prefer_ipv4_upstream) {
                    Some(r) => r,
                    None => {
                        warn!(path = %route.path, addr = %addr.display_host_port(), "mux xudp addr unresolved; dropping");
                        return Ok(());
                    },
                },
                None => *default_target,
            };
            send_udp_payload(socket, &payload, dst, &state.user_counters, route.protocol).await;
        },
    }
    Ok(())
}

async fn handle_end(state: &mut MuxState, session_id: u16) {
    finish_sub(state, session_id).await;
}

async fn finish_sub(state: &mut MuxState, session_id: u16) {
    if let Some(mut sub) = state.sub_conns.remove(&session_id) {
        if let SubConnKind::Tcp(mut w) = sub.kind {
            let _ = w.shutdown().await;
        }
        // Dropping `sub` aborts its reader_task via AbortOnDrop.
    }
}

async fn send_udp_payload(
    socket: &UdpSocket,
    payload: &[u8],
    dst: SocketAddr,
    user_counters: &PerUserCounters,
    protocol: Protocol,
) {
    user_counters.udp_in(protocol).increment(payload.len() as u64);
    if let Err(error) = socket.send_to(payload, dst).await {
        debug!(%dst, error = %error, "mux udp send_to failed");
    }
}

fn resolve_packet_addr(
    dns_cache: &DnsCache,
    addr: &TargetAddr,
    prefer_ipv4_upstream: bool,
) -> Option<SocketAddr> {
    match addr {
        TargetAddr::Socket(sa) => {
            if prefer_ipv4_upstream && sa.is_ipv6() {
                return None;
            }
            Some(*sa)
        },
        TargetAddr::Domain(host, port) => {
            dns_cache.lookup_one(host, *port, prefer_ipv4_upstream)
        },
    }
}

fn bind_unconnected_udp(
    target: SocketAddr,
    fwmark: Option<u32>,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<UdpSocket> {
    let socket = bind_nat_udp_socket(target, outbound_ipv6)
        .context("failed to bind mux udp upstream socket")?;
    apply_fwmark_if_needed(&socket, fwmark)
        .with_context(|| format!("failed to apply fwmark {fwmark:?} to mux udp socket"))?;
    Ok(socket)
}

async fn send_end<Msg>(
    tx: &mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    session_id: u16,
    error: bool,
) -> Result<()>
where
    Msg: Send + 'static,
{
    let mut frame = BytesMut::with_capacity(8);
    let option = if error { OPTION_ERROR } else { 0 };
    encode_frame(&mut frame, session_id, SessionStatus::End, option, None, None, None);
    tx.send(make_binary(frame.freeze()))
        .await
        .map_err(|_| anyhow!("failed to queue mux End frame"))?;
    Ok(())
}

// Suppress unused import warnings for items referenced only in future extensions.
#[allow(dead_code)]
fn _assert_mux_error(_e: MuxError) {}
