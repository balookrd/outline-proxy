use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::OwnedReadHalf,
    sync::{Notify, mpsc},
};
use tracing::{debug, warn};

use super::frames::send_end;
use super::state::{
    MuxReaderHarvest, MuxRouteCtx, MuxServerCtx, MuxState, MuxSubConn, SubConnKind,
};
use super::super::super::{
    connect::connect_tcp_target,
    relay::{GREEDY_DRAIN_TARGET, try_read_now_into_slice},
    scratch::TcpRelayBuf,
};
use crate::{
    metrics::{AppProtocol, Metrics, Protocol, Transport},
    protocol::{
        TargetAddr,
        vless_mux::{OPTION_DATA, SessionStatus, encode_frame},
    },
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn open_tcp_sub<Msg>(
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
        state
            .user_counters
            .tcp_in(AppProtocol::Vless, route.protocol)
            .increment(initial.len() as u64);
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

pub(super) async fn run_tcp_reader<Msg>(
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
    let target_to_client = user_counters.tcp_out(AppProtocol::Vless, protocol);
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
                // Greedy-drain: collapse multiple TCP-segment-sized
                // upstream reads into a single mux frame so the per-frame
                // mux header (`encode_frame`), metric record and mpsc push
                // amortise across the same payload size as the SS path.
                let mut total = read;
                let cap = buf.len().min(GREEDY_DRAIN_TARGET);
                while total < cap {
                    match try_read_now_into_slice(&mut reader, &mut buf[total..cap]).await {
                        Ok(Some(0)) => break,
                        Ok(Some(n)) => total += n,
                        Ok(None) => break,
                        Err(error) => {
                            debug!(session_id, error = %error, "mux tcp upstream drain error");
                            break;
                        },
                    }
                }
                target_to_client.increment(total as u64);
                frame_buf.reserve(total + 16);
                encode_frame(
                    &mut frame_buf,
                    session_id,
                    SessionStatus::Keep,
                    OPTION_DATA,
                    None,
                    None,
                    Some(&buf[..total]),
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
    frame_buf.reserve(6);
    encode_frame(&mut frame_buf, session_id, SessionStatus::End, 0, None, None, None);
    let _ = tx.send(make_binary(frame_buf.split().freeze())).await;
    MuxReaderHarvest::Closed
}
