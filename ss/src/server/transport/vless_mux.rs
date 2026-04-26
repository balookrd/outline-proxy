use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        UdpSocket,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tracing::{debug, warn};

use super::super::resumption::{ParkedMuxSubConn, ParkedMuxSubKind, ParkedVlessMux};

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
    connect::{connect_tcp_target, resolve_udp_target},
    constants::MAX_UDP_PAYLOAD_SIZE,
    dns_cache::DnsCache,
    nat::bind_nat_udp_socket,
    scratch::{TcpRelayBuf, UdpRecvBuf},
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

/// Output of a sub-connection reader task. Distinguishes the natural
/// EOF / closed path (no harvest possible) from a caller-requested
/// cancel where the underlying reader half (TCP only) is returned for
/// re-attach inside an [`OrphanRegistry`].
pub(super) enum MuxReaderHarvest {
    /// Reader returned naturally — upstream EOF or send-error on the
    /// outbound channel. The reader is consumed.
    Closed,
    /// Caller fired `cancel.notify_one()` before EOF and the TCP
    /// reader half was harvested. Only TCP sub-connections produce
    /// this variant; UDP sub-conns share the socket via `Arc` and
    /// have nothing to hand off.
    TcpCancelled(OwnedReadHalf),
    /// UDP cancel: nothing to harvest (the socket already lives in
    /// the parent `SubConnKind::Udp`). Distinct variant rather than
    /// reusing `Closed` so the harvest path can tell "loop exited
    /// because we asked it to" from "loop exited because the channel
    /// died on its own".
    UdpCancelled,
}

struct MuxSubConn {
    kind: SubConnKind,
    /// Notify used to ask the reader task to stop and (for TCP) hand
    /// over its read half. Cloned by the spawn site; calling
    /// `notify_one()` once is enough — the task selects on it.
    cancel: Arc<Notify>,
    /// Reader task handle. `None` after [`MuxSubConn::take_reader_task`]
    /// has moved it out (park path). On drop the leftover `Some` is
    /// aborted as a safety net, mirroring the previous `AbortOnDrop`.
    reader_task: Option<JoinHandle<MuxReaderHarvest>>,
}

impl Drop for MuxSubConn {
    fn drop(&mut self) {
        // Safety net for `?`-return / panic paths inside `MuxState`.
        // Mirrors the previous `AbortOnDrop` behaviour so a UDP reader
        // (which would otherwise block on `recv_from` forever) does
        // not survive the parent `MuxState`. Cleanup paths that need
        // to keep the task alive go through [`Self::into_parts`].
        if let Some(handle) = self.reader_task.take() {
            handle.abort();
        }
    }
}

impl MuxSubConn {
    /// Decomposes the sub-conn into its three pieces, suppressing the
    /// auto-abort. The caller takes responsibility for the reader
    /// task's lifecycle and the writer/socket cleanup.
    ///
    /// Used by both [`MuxState::shutdown`] and
    /// [`MuxState::harvest_into_parked`]; the alternative — an
    /// `Option<SubConnKind>` field — would force the hot
    /// `dispatch_frame` path through extra unwraps for no benefit.
    fn into_parts(self) -> (SubConnKind, Option<JoinHandle<MuxReaderHarvest>>, Arc<Notify>) {
        let me = std::mem::ManuallyDrop::new(self);
        // SAFETY: `me` is wrapped in ManuallyDrop so its `Drop` impl
        // does not run; each field is therefore read out exactly once
        // and then ownership transfers to the returned tuple.
        unsafe {
            let kind = std::ptr::read(&me.kind);
            let task = std::ptr::read(&me.reader_task);
            let cancel = std::ptr::read(&me.cancel);
            (kind, task, cancel)
        }
    }
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
        // reader sees EOF, then aborts every reader task. UDP readers
        // would otherwise sit in `recv_from` forever — they have no
        // shutdown signal at the socket level.
        for (_, sub) in self.sub_conns.drain() {
            let (kind, task, _cancel) = sub.into_parts();
            if let SubConnKind::Tcp(mut w) = kind {
                let _ = w.shutdown().await;
            }
            if let Some(handle) = task {
                handle.abort();
            }
        }
    }

    /// Atomically harvests every sub-connection's writer/socket and
    /// reader half into a [`ParkedVlessMux`] for the orphan registry.
    /// Each sub-conn's reader task is asked to stop via `cancel.notify_one()`,
    /// then awaited; TCP harvests yield the `OwnedReadHalf`, UDP
    /// harvests are handle-only.
    ///
    /// Sub-conns whose reader task already exited on its own
    /// (closed / cancelled before harvest, or panicked) are skipped:
    /// their writer/socket is dropped normally, and the
    /// post-condition becomes "park a possibly-pruned mux". Callers
    /// that need an all-or-nothing guarantee should consult
    /// [`Self::is_parkable`] first.
    pub async fn harvest_into_parked(
        mut self,
        owner: Arc<str>,
        protocol: Protocol,
    ) -> ParkedVlessMux {
        let mut parked_subs = HashMap::with_capacity(self.sub_conns.len());
        for (id, sub) in self.sub_conns.drain() {
            let (kind, task, cancel) = sub.into_parts();
            cancel.notify_one();
            let task = match task {
                Some(t) => t,
                None => continue,
            };
            let harvest = task.await;
            let parked_kind = match (kind, harvest) {
                (SubConnKind::Tcp(writer), Ok(MuxReaderHarvest::TcpCancelled(reader))) => {
                    ParkedMuxSubKind::Tcp { writer, reader }
                },
                (SubConnKind::Udp { socket, default_target }, Ok(MuxReaderHarvest::UdpCancelled)) => {
                    ParkedMuxSubKind::Udp { socket, default_target }
                },
                (_, Ok(MuxReaderHarvest::Closed)) => {
                    debug!(session_id = id, "mux sub-conn already closed; skipping for park");
                    continue;
                },
                (k, Ok(_other)) => {
                    debug!(
                        session_id = id,
                        kind_label = sub_conn_kind_label(&k),
                        "mux harvest type mismatch (cancel race?); skipping sub-conn"
                    );
                    continue;
                },
                (_, Err(error)) => {
                    debug!(session_id = id, error = %error, "mux reader task join failed; skipping for park");
                    continue;
                },
            };
            parked_subs.insert(id, ParkedMuxSubConn { kind: parked_kind });
        }
        ParkedVlessMux {
            sub_conns: parked_subs,
            buffer: self.buffer,
            user: self.user,
            owner,
            protocol,
            user_counters: self.user_counters,
        }
    }

    /// Returns `true` when there is at least one live sub-connection
    /// to preserve. Empty muxes are not worth a registry entry.
    pub fn is_parkable(&self) -> bool {
        !self.sub_conns.is_empty()
    }
}

fn sub_conn_kind_label(kind: &SubConnKind) -> &'static str {
    match kind {
        SubConnKind::Tcp(_) => "tcp",
        SubConnKind::Udp { .. } => "udp",
    }
}

/// Re-attaches a parked mux into a freshly-started client stream.
///
/// Re-spawns one reader task per sub-connection against the supplied
/// outbound channel (cloned once per task) and restores the partial
/// frame buffer that was preserved at park time. Returns the live
/// [`MuxState`] ready to be installed in `UpstreamSession::Mux`.
pub(super) fn attach_parked<Msg>(
    parked: ParkedVlessMux,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
) -> MuxState
where
    Msg: Send + 'static,
{
    let user_label = parked.user.label_arc();
    let mut mux = MuxState::new(parked.user, Arc::clone(&parked.user_counters));
    mux.buffer = parked.buffer;
    for (id, parked_sub) in parked.sub_conns {
        let cancel = Arc::new(Notify::new());
        let cancel_for_task = Arc::clone(&cancel);
        match parked_sub.kind {
            ParkedMuxSubKind::Tcp { writer, reader } => {
                let task = tokio::spawn(run_tcp_reader(
                    id,
                    reader,
                    tx.clone(),
                    make_binary,
                    Arc::clone(&metrics),
                    protocol,
                    Arc::clone(&user_label),
                    cancel_for_task,
                ));
                mux.sub_conns.insert(
                    id,
                    MuxSubConn {
                        kind: SubConnKind::Tcp(writer),
                        cancel,
                        reader_task: Some(task),
                    },
                );
            },
            ParkedMuxSubKind::Udp { socket, default_target } => {
                let reader_socket = Arc::clone(&socket);
                let task = tokio::spawn(run_udp_reader(
                    id,
                    reader_socket,
                    tx.clone(),
                    make_binary,
                    Arc::clone(&metrics),
                    protocol,
                    Arc::clone(&user_label),
                    cancel_for_task,
                ));
                mux.sub_conns.insert(
                    id,
                    MuxSubConn {
                        kind: SubConnKind::Udp { socket, default_target },
                        cancel,
                        reader_task: Some(task),
                    },
                );
            },
        }
    }
    mux
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
    let cancel = Arc::new(Notify::new());
    let cancel_for_task = Arc::clone(&cancel);
    let reader_task = tokio::spawn(run_tcp_reader(
        session_id,
        reader,
        tx_task,
        make_binary,
        metrics,
        protocol,
        user_label,
        cancel_for_task,
    ));

    state.sub_conns.insert(
        session_id,
        MuxSubConn {
            kind: SubConnKind::Tcp(writer),
            cancel,
            reader_task: Some(reader_task),
        },
    );
    Ok(())
}

async fn run_tcp_reader<Msg>(
    session_id: u16,
    mut reader: OwnedReadHalf,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    metrics: Arc<Metrics>,
    protocol: Protocol,
    user: Arc<str>,
    cancel: Arc<Notify>,
) -> MuxReaderHarvest
where
    Msg: Send + 'static,
{
    let user_counters = metrics.user_counters(&user);
    let target_to_client = user_counters.tcp_out(protocol);
    let mut buf = TcpRelayBuf::take();
    let mut frame_buf = BytesMut::with_capacity(16 * 1024 + 16);
    loop {
        tokio::select! {
            biased;
            _ = cancel.notified() => {
                // No End frame here — the caller is moving the reader
                // into the orphan registry so the server can resume the
                // sub-conn on the next client stream. Sending End would
                // race the reconnect.
                return MuxReaderHarvest::TcpCancelled(reader);
            }
            read_result = reader.read(&mut *buf) => {
                let read = match read_result {
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
                    return MuxReaderHarvest::Closed;
                }
            }
        }
    }
    frame_buf.reserve(6);
    encode_frame(&mut frame_buf, session_id, SessionStatus::End, 0, None, None, None);
    let _ = tx.send(make_binary(frame_buf.split().freeze())).await;
    MuxReaderHarvest::Closed
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
    let cancel = Arc::new(Notify::new());
    let cancel_for_task = Arc::clone(&cancel);
    let reader_task = tokio::spawn(run_udp_reader(
        session_id,
        reader_socket,
        tx_task,
        make_binary,
        metrics,
        protocol,
        user_label,
        cancel_for_task,
    ));

    state.sub_conns.insert(
        session_id,
        MuxSubConn {
            kind: SubConnKind::Udp { socket: Arc::clone(&socket), default_target },
            cancel,
            reader_task: Some(reader_task),
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
    cancel: Arc<Notify>,
) -> MuxReaderHarvest
where
    Msg: Send + 'static,
{
    let user_counters = metrics.user_counters(&user);
    let target_to_client = user_counters.udp_out(protocol);
    let mut buf = UdpRecvBuf::take();
    let mut frame_buf = BytesMut::with_capacity(MAX_UDP_PAYLOAD_SIZE + 32);
    loop {
        tokio::select! {
            biased;
            _ = cancel.notified() => {
                // Park: socket is shared via Arc with the parent
                // SubConnKind::Udp, so there is nothing to hand over.
                // Packets that arrive between cancel and resume are
                // dropped (UDP is loss-tolerant); a future revision
                // can buffer them per the spec's back-buffer policy.
                return MuxReaderHarvest::UdpCancelled;
            }
            recv_result = socket.recv_from(&mut *buf) => {
                let (read, from) = match recv_result {
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
                    return MuxReaderHarvest::Closed;
                }
            }
        }
    }
    frame_buf.reserve(6);
    encode_frame(&mut frame_buf, session_id, SessionStatus::End, 0, None, None, None);
    let _ = tx.send(make_binary(frame_buf.split().freeze())).await;
    MuxReaderHarvest::Closed
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
    if let Some(sub) = state.sub_conns.remove(&session_id) {
        let (kind, task, _cancel) = sub.into_parts();
        if let SubConnKind::Tcp(mut w) = kind {
            let _ = w.shutdown().await;
        }
        if let Some(handle) = task {
            handle.abort();
        }
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
