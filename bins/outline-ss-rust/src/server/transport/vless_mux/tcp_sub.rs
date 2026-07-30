use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::{
    io::AsyncWriteExt,
    net::tcp::OwnedReadHalf,
    sync::{Notify, mpsc},
};
use tracing::{debug, warn};

use super::super::super::{
    connect::connect_tcp_target,
    relay::{GREEDY_DRAIN_TARGET, try_read_now_into_slice},
    scratch::TcpRelayBuf,
};
use super::frames::send_end;
use super::state::{
    MuxClientMetrics, MuxReaderHarvest, MuxRouteCtx, MuxServerCtx, MuxState, MuxSubConn,
    SubConnKind, client_metrics,
};
use crate::{
    metrics::{AppProtocol, Protocol, Transport},
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
    let target_display = target.to_string();
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
        if let Some(counters) = state.accounting.counted(&state.user_counters) {
            counters
                .tcp_in(AppProtocol::Vless, route.protocol)
                .increment(initial.len() as u64);
        }
        writer
            .write_all(&initial)
            .await
            .context("mux tcp initial write failed")?;
    }

    let tx_task = tx.clone();
    let client = client_metrics(state.accounting, &server.metrics, &state.user_counters);
    let protocol = route.protocol;
    let cancel = Arc::new(Notify::new());
    let cancel_for_task = Arc::clone(&cancel);
    let reader_task = tokio::spawn(run_tcp_reader(
        session_id,
        reader,
        tx_task,
        make_binary,
        client,
        protocol,
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

/// `client` is `None` on a relayed mux: the edge that terminates the client
/// session has already counted these bytes and frames once (see
/// [`MuxClientMetrics`]).
pub(super) async fn run_tcp_reader<Msg>(
    session_id: u16,
    mut reader: OwnedReadHalf,
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
        .map(|client| client.counters.tcp_out(AppProtocol::Vless, protocol));
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
            ready = reader.readable() => {
                if let Err(error) = ready {
                    debug!(session_id, error = %error, "mux tcp upstream readiness error");
                    break;
                }
                // Allocate from the pool only once data is ready, so an idle
                // sub-conn holds no per-direction relay buffer; the buffer
                // returns to the pool before the next park.
                let mut buf = TcpRelayBuf::take();
                let read = match reader.try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
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
                if let Some(counter) = target_to_client.as_ref() {
                    counter.increment(total as u64);
                }
                // Build the frame on demand so an idle sub-conn holds no
                // encode buffer either.
                let mut frame_buf = BytesMut::with_capacity(total + 16);
                // The relay buffer is sized at MAX_FRAME_DATA_SIZE, so this
                // cannot overflow the frame; a future resize that breaks the
                // invariant tears the sub-conn down instead of emitting a
                // frame the peer would reject mid-stream.
                if let Err(error) = encode_frame(
                    &mut frame_buf,
                    session_id,
                    SessionStatus::Keep,
                    OPTION_DATA,
                    None,
                    None,
                    Some(&buf[..total]),
                ) {
                    debug!(session_id, error = %error, "mux tcp downlink frame encode failed");
                    break;
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
