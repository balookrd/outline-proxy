use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use tokio::{io::AsyncWriteExt, sync::mpsc};
use tracing::{debug, warn};

use super::state::{MAX_MUX_SUB_CONNS, MuxRouteCtx, MuxServerCtx, MuxState, SubConnKind};
use super::tcp_sub::open_tcp_sub;
use super::udp_sub::{open_udp_sub, resolve_packet_addr, send_udp_payload};
use crate::protocol::vless_mux::{
    self, FrameMeta, Network, OPTION_ERROR, ParsedFrame, SessionStatus, encode_frame, parse_frame,
};

/// Maximum number of bytes we will buffer while waiting for a complete frame.
const MAX_MUX_FRAME_BUFFER: usize = 2 * (vless_mux::MAX_FRAME_DATA_SIZE + 64);

pub(in crate::server::transport) async fn handle_client_bytes<Msg>(
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
                    return Err(anyhow!("mux frame buffer overflow: {} bytes", state.buffer.len()));
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
        SessionStatus::New => handle_new(state, meta, data, server, route, tx, make_binary).await,
        SessionStatus::Keep => handle_keep(state, meta, data, server, route).await,
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
    let target = meta
        .target
        .clone()
        .ok_or_else(|| anyhow!("mux New frame missing target"))?;

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
            state
                .user_counters
                .tcp_in(crate::metrics::AppProtocol::Vless, route.protocol)
                .increment(payload.len() as u64);
            if let Err(error) = writer.write_all(&payload).await {
                debug!(session_id = meta.session_id, error = %error, "mux tcp upstream write error");
                finish_sub(state, meta.session_id).await;
            }
        },
        SubConnKind::Udp { socket, default_target } => {
            let dst = match meta.target.as_ref() {
                Some(addr) => match resolve_packet_addr(
                    server.dns_cache.as_ref(),
                    addr,
                    server.prefer_ipv4_upstream,
                ) {
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

pub(super) async fn send_end<Msg>(
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
