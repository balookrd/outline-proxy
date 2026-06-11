use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::metrics::{AppProtocol, Metrics, Protocol, Transport};

use super::super::constants::WS_CONTROL_FLUSH_INTERVAL_SECS;
use super::ws_socket::WsSocket;

pub(super) async fn run_ws_writer<T: WsSocket>(
    mut writer: T::Writer,
    mut outbound_ctrl_rx: mpsc::Receiver<T::Msg>,
    mut outbound_data_rx: mpsc::Receiver<T::Msg>,
    metrics: Arc<Metrics>,
    transport_kind: Transport,
    protocol: Protocol,
    app_protocol: AppProtocol,
) -> Result<()> {
    let result = async {
        // Periodically drain any control-frame responses the transport
        // buffered (chiefly a Pong the split reader queued in reply to a
        // client keepalive Ping). On a quiet datagram channel neither
        // `recv` ever fires, so without this tick the reactive Pong would
        // sit unsent and the client's read-idle watchdog would trip. The
        // flush delivers it WITHOUT emitting a server-originated Ping —
        // unsafe on H3, where it races stream teardown on a `shuffle_timer`
        // reroll and escalates to a connection-level `H3_INTERNAL_ERROR`.
        // The `biased` ordering keeps the flush a last resort: a closed
        // ctrl/data channel (teardown) is observed first, so we exit
        // rather than write into a stream that is already finishing.
        let mut flush_tick =
            tokio::time::interval(Duration::from_secs(WS_CONTROL_FLUSH_INTERVAL_SECS));
        flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        flush_tick.tick().await; // skip the immediate first tick

        let mut ctrl_open = true;
        loop {
            if ctrl_open {
                tokio::select! {
                    biased;
                    msg = outbound_ctrl_rx.recv() => match msg {
                        Some(m) => T::send(&mut writer, m).await?,
                        None => ctrl_open = false,
                    },
                    msg = outbound_data_rx.recv() => match msg {
                        Some(m) => send_data::<T>(
                            &mut writer, m, &metrics, transport_kind, protocol, app_protocol,
                        ).await?,
                        None => break,
                    },
                    _ = flush_tick.tick() => T::flush(&mut writer).await?,
                }
            } else {
                tokio::select! {
                    biased;
                    msg = outbound_data_rx.recv() => match msg {
                        Some(m) => send_data::<T>(
                            &mut writer, m, &metrics, transport_kind, protocol, app_protocol,
                        ).await?,
                        None => break,
                    },
                    _ = flush_tick.tick() => T::flush(&mut writer).await?,
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    T::finish(&mut writer).await;
    result
}

/// Records the binary-frame metric (when applicable) and writes a single
/// downlink message. Shared by the ctrl-open and ctrl-closed select arms so
/// the data-send path stays identical regardless of control-channel state.
async fn send_data<T: WsSocket>(
    writer: &mut T::Writer,
    msg: T::Msg,
    metrics: &Metrics,
    transport_kind: Transport,
    protocol: Protocol,
    app_protocol: AppProtocol,
) -> Result<()> {
    if let Some(len) = T::binary_len(&msg) {
        metrics.record_websocket_binary_frame(transport_kind, protocol, app_protocol, "out", len);
    }
    T::send(writer, msg).await
}
