use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc},
};
use tracing::{debug, warn};

use super::super::super::{
    connect::resolve_udp_target, dns_cache::DnsCache, nat::bind_nat_udp_socket, scratch::UdpRecvBuf,
};
use super::frames::send_end;
use super::state::{
    MuxReaderHarvest, MuxRouteCtx, MuxServerCtx, MuxState, MuxSubConn, SubConnKind,
};
use crate::{
    fwmark::apply_fwmark_if_needed,
    metrics::{AppProtocol, Metrics, PerUserCounters, Protocol, Transport},
    outbound::OutboundIpv6,
    protocol::{
        TargetAddr,
        vless_mux::{Network, OPTION_DATA, SessionStatus, encode_frame},
    },
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn open_udp_sub<Msg>(
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
    let default_target =
        match resolve_udp_target(server.dns_cache.as_ref(), &target, server.prefer_ipv4_upstream)
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

    let socket = match bind_unconnected_udp(
        default_target,
        state.user.fwmark(),
        server.outbound_ipv6.as_deref(),
    ) {
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
            kind: SubConnKind::Udp {
                socket: Arc::clone(&socket),
                default_target,
            },
            cancel,
            reader_task: Some(reader_task),
        },
    );

    if let Some(payload) = initial
        && !payload.is_empty()
    {
        send_udp_payload(&socket, &payload, default_target, &state.user_counters, route.protocol)
            .await;
    }
    Ok(())
}

pub(super) async fn run_udp_reader<Msg>(
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
    let target_to_client = user_counters.udp_out(AppProtocol::Vless, protocol);
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
            ready = socket.readable() => {
                if let Err(error) = ready {
                    debug!(session_id, error = %error, "mux udp readiness error");
                    break;
                }
                // Allocate from the pool only once a datagram is ready, so an
                // idle sub-conn holds no per-session receive buffer; the
                // buffer returns to the pool before the next park.
                let mut buf = UdpRecvBuf::take();
                let (read, from) = match socket.try_recv_from(&mut *buf) {
                    Ok(v) => v,
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
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
                // Build the frame on demand so an idle sub-conn holds no
                // encode buffer either.
                let mut frame_buf = BytesMut::with_capacity(read + 32);
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
                metrics.record_websocket_binary_frame(
                    Transport::Tcp,
                    protocol,
                    AppProtocol::Vless,
                    "out",
                    frame.len(),
                );
                if tx.send(make_binary(frame)).await.is_err() {
                    return MuxReaderHarvest::Closed;
                }
            }
        }
    }
    let mut frame_buf = BytesMut::with_capacity(6);
    encode_frame(&mut frame_buf, session_id, SessionStatus::End, 0, None, None, None);
    let _ = tx.send(make_binary(frame_buf.split().freeze())).await;
    MuxReaderHarvest::Closed
}

pub(super) async fn send_udp_payload(
    socket: &UdpSocket,
    payload: &[u8],
    dst: SocketAddr,
    user_counters: &PerUserCounters,
    protocol: Protocol,
) {
    user_counters
        .udp_in(AppProtocol::Vless, protocol)
        .increment(payload.len() as u64);
    if let Err(error) = socket.send_to(payload, dst).await {
        debug!(%dst, error = %error, "mux udp send_to failed");
    }
}

pub(super) fn resolve_packet_addr(
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
        TargetAddr::Domain(host, port) => dns_cache.lookup_one(host, *port, prefer_ipv4_upstream),
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
