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
    MuxClientMetrics, MuxReaderHarvest, MuxRouteCtx, MuxServerCtx, MuxState, MuxSubConn,
    SubConnKind, client_metrics,
};
use crate::{
    fwmark::apply_fwmark_if_needed,
    metrics::{AppProtocol, PerUserCounters, Protocol, Transport},
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
    let client = client_metrics(state.accounting, &server.metrics, &state.user_counters);
    let protocol = route.protocol;
    let reader_socket = Arc::clone(&socket);
    let cancel = Arc::new(Notify::new());
    let cancel_for_task = Arc::clone(&cancel);
    let reader_task = tokio::spawn(run_udp_reader(
        session_id,
        reader_socket,
        tx_task,
        make_binary,
        client,
        protocol,
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
        send_udp_payload(
            &socket,
            &payload,
            default_target,
            state.accounting.counted(&state.user_counters),
            route.protocol,
        )
        .await;
    }
    Ok(())
}

/// `client` is `None` on a relayed mux: the edge that terminates the client
/// session has already counted these bytes and frames once (see
/// [`MuxClientMetrics`]).
pub(super) async fn run_udp_reader<Msg>(
    session_id: u16,
    socket: Arc<UdpSocket>,
    tx: mpsc::Sender<Msg>,
    make_binary: fn(Bytes) -> Msg,
    client: Option<MuxClientMetrics>,
    protocol: Protocol,
    cancel: Arc<Notify>,
) -> MuxReaderHarvest
where
    Msg: Send + 'static,
{
    let target_to_client = client
        .as_ref()
        .map(|client| client.counters.udp_out(AppProtocol::Vless, protocol));
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
                let (read, from) = match socket.try_recv_from(&mut buf) {
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
                if let Some(counter) = target_to_client.as_ref() {
                    counter.increment(read as u64);
                }
                let src = TargetAddr::from(from);
                // Build the frame on demand so an idle sub-conn holds no
                // encode buffer either.
                let mut frame_buf = BytesMut::with_capacity(read + 32);
                // A datagram larger than one mux frame can hold has no valid
                // encoding: drop it (UDP is loss-tolerant) rather than emit a
                // frame the peer rejects, which would kill the whole carrier.
                if let Err(error) = encode_frame(
                    &mut frame_buf,
                    session_id,
                    SessionStatus::Keep,
                    OPTION_DATA,
                    Some(Network::Udp),
                    Some(&src),
                    Some(&buf[..read]),
                ) {
                    debug!(session_id, error = %error, "mux udp downlink frame encode failed");
                    continue;
                }
                let frame = frame_buf.split().freeze();
                if let Some(client) = client.as_ref() {
                    client.metrics.record_websocket_binary_frame(
                        Transport::Tcp,
                        protocol,
                        AppProtocol::Vless,
                        "down",
                        frame.len(),
                    );
                }
                if tx.send(make_binary(frame)).await.is_err() {
                    return MuxReaderHarvest::Closed;
                }
            }
        }
    }
    let mut frame_buf = BytesMut::with_capacity(6);
    encode_frame(&mut frame_buf, session_id, SessionStatus::End, 0, None, None, None)
        .expect("End frame carries neither target nor data");
    let _ = tx.send(make_binary(frame_buf.split().freeze())).await;
    MuxReaderHarvest::Closed
}

/// `user_counters` is `None` on a relayed mux, where the edge already counted
/// this payload (see [`super::state::MuxAccounting`]).
pub(super) async fn send_udp_payload(
    socket: &UdpSocket,
    payload: &[u8],
    dst: SocketAddr,
    user_counters: Option<&PerUserCounters>,
    protocol: Protocol,
) {
    if let Some(counters) = user_counters {
        counters
            .udp_in(AppProtocol::Vless, protocol)
            .increment(payload.len() as u64);
    }
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
        TargetAddr::Domain(host, port) => dns_cache.lookup_one(host, *port, prefer_ipv4_upstream),
        ip_target => {
            let sa = ip_target.socket_addr()?;
            if prefer_ipv4_upstream && sa.is_ipv6() {
                return None;
            }
            Some(sa)
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
