use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{net::UdpSocket, sync::mpsc};
use tracing::{info, warn};

use crate::{
    fwmark::apply_fwmark_if_needed,
    metrics::{Metrics, Protocol},
    outbound::OutboundIpv6,
    protocol::vless::{self, VlessUser},
};

use super::{
    super::{connect::resolve_udp_target, constants::MAX_UDP_PAYLOAD_SIZE, nat::bind_nat_udp_socket},
    vless::{UpstreamSession, VlessRelayState, VlessWsOutbound, VlessWsRouteCtx, VlessWsServerCtx},
};

pub(super) const MAX_VLESS_UDP_CLIENT_BUFFER: usize = MAX_UDP_PAYLOAD_SIZE + 2;

pub(super) async fn establish_vless_udp_upstream<Msg>(
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
    info!(user = user.label(), path = %route.path, target = %target_display, "vless udp target");

    let resolved = match resolve_udp_target(
        server.dns_cache.as_ref(),
        &target,
        server.prefer_ipv4_upstream,
    )
    .await
    {
        Ok(addr) => addr,
        Err(error) => {
            warn!(
                user = user.label(),
                path = %route.path,
                target = %target_display,
                error = %error,
                "vless udp dns resolution failed; sending try-again close"
            );
            let _ = outbound.ctrl_tx.send((outbound.make_try_again_close)()).await;
            return Err(error).context("vless udp dns resolution failed");
        },
    };

    let socket = match bind_and_connect_udp(resolved, user.fwmark(), server.outbound_ipv6.as_deref())
        .await
    {
        Ok(socket) => socket,
        Err(error) => {
            warn!(
                user = user.label(),
                path = %route.path,
                target = %target_display,
                error = %error,
                "vless udp bind/connect failed; sending try-again close"
            );
            let _ = outbound.ctrl_tx.send((outbound.make_try_again_close)()).await;
            return Err(error).context("vless udp upstream bind/connect failed");
        },
    };

    let socket = Arc::new(socket);

    outbound
        .data_tx
        .send((outbound.make_binary)(Bytes::from_static(&[vless::VERSION, 0x00])))
        .await
        .map_err(|error| anyhow!("failed to queue vless response header: {error}"))?;

    let tx = outbound.data_tx.clone();
    let metrics = Arc::clone(&server.metrics);
    let user_id = user.label_arc();
    let protocol = route.protocol;
    let reader_socket = Arc::clone(&socket);
    state.upstream_to_client = Some(tokio::spawn(async move {
        relay_vless_udp_upstream_to_client(
            reader_socket,
            tx,
            outbound.make_binary,
            outbound.make_close,
            metrics,
            protocol,
            user_id,
        )
        .await
    }));
    state.authenticated_user = Some(user);
    state.upstream = UpstreamSession::Udp(Arc::clone(&socket));

    let leftover = state.header_buffer.split_off(request.consumed);
    state.header_buffer.clear();
    if !leftover.is_empty() {
        let leftover_bytes = Bytes::from(leftover);
        forward_vless_udp_client_frames(
            &mut state.udp_client_buffer,
            &leftover_bytes,
            socket.as_ref(),
            &server.metrics,
            route.protocol,
            state.authenticated_user.as_ref(),
            &route.path,
        )
        .await?;
    }

    Ok(())
}

async fn bind_and_connect_udp(
    target: SocketAddr,
    fwmark: Option<u32>,
    outbound_ipv6: Option<&OutboundIpv6>,
) -> Result<UdpSocket> {
    let socket = bind_nat_udp_socket(target, outbound_ipv6)
        .context("failed to bind vless udp upstream socket")?;
    apply_fwmark_if_needed(&socket, fwmark)
        .with_context(|| format!("failed to apply fwmark {fwmark:?} to vless udp socket"))?;
    socket
        .connect(&target)
        .await
        .with_context(|| format!("failed to connect vless udp socket to {target}"))?;
    Ok(socket)
}

pub(super) async fn forward_vless_udp_client_frames(
    buffer: &mut BytesMut,
    data: &Bytes,
    socket: &UdpSocket,
    metrics: &Metrics,
    protocol: Protocol,
    user: Option<&VlessUser>,
    path: &str,
) -> Result<()> {
    buffer.extend_from_slice(data);
    loop {
        if buffer.len() < 2 {
            break;
        }
        let len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
        if len > MAX_UDP_PAYLOAD_SIZE {
            warn!(path = %path, len, "vless udp client datagram exceeds maximum; dropping session");
            return Err(anyhow!("vless udp datagram too large: {len}"));
        }
        if buffer.len() < 2 + len {
            if buffer.capacity() < 2 + len {
                buffer.reserve(2 + len - buffer.capacity());
            }
            break;
        }
        let _ = buffer.split_to(2);
        let payload = buffer.split_to(len).freeze();
        if let Some(user) = user {
            metrics.record_udp_payload_bytes(
                user.label_arc(),
                protocol,
                "client_to_target",
                payload.len(),
            );
        }
        match socket.send(&payload).await {
            Ok(sent) if sent == payload.len() => {},
            Ok(sent) => {
                warn!(path = %path, sent, expected = payload.len(), "vless udp short send");
            },
            Err(error) => {
                warn!(path = %path, error = %error, "vless udp send failed");
                return Err(error).context("failed to send vless udp datagram upstream");
            },
        }
    }
    if buffer.len() > MAX_VLESS_UDP_CLIENT_BUFFER {
        return Err(anyhow!("vless udp client buffer overflow: {}", buffer.len()));
    }
    Ok(())
}

async fn relay_vless_udp_upstream_to_client<Msg>(
    socket: Arc<UdpSocket>,
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
    let user_counters = metrics.user_counters(&user_id);
    let target_to_client = user_counters.udp_out(protocol);
    let mut buffer = vec![0_u8; MAX_UDP_PAYLOAD_SIZE];
    loop {
        let read = match socket.recv(&mut buffer).await {
            Ok(n) => n,
            Err(error) => {
                let _ = tx.send(make_close()).await;
                return Err(error).context("failed to read from vless udp upstream");
            },
        };
        if read == 0 {
            continue;
        }
        target_to_client.increment(read as u64);
        let mut framed = BytesMut::with_capacity(2 + read);
        framed.put_u16(read as u16);
        framed.extend_from_slice(&buffer[..read]);
        tx.send(make_binary(framed.freeze()))
            .await
            .map_err(|error| anyhow!("failed to queue vless udp websocket frame: {error}"))?;
    }
}
