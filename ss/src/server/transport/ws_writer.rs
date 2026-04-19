use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;

use crate::metrics::{Metrics, Protocol, Transport};

use super::ws_socket::WsSocket;

pub(super) async fn run_ws_writer<T: WsSocket>(
    mut writer: T::Writer,
    mut outbound_ctrl_rx: mpsc::Receiver<T::Msg>,
    mut outbound_data_rx: mpsc::Receiver<T::Msg>,
    metrics: Arc<Metrics>,
    transport_kind: Transport,
    protocol: Protocol,
) -> Result<()> {
    let result = async {
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
                        Some(m) => {
                            if let Some(len) = T::binary_len(&m) {
                                metrics.record_websocket_binary_frame(
                                    transport_kind, protocol, "out", len,
                                );
                            }
                            T::send(&mut writer, m).await?;
                        }
                        None => break,
                    },
                }
            } else {
                let Some(m) = outbound_data_rx.recv().await else {
                    break;
                };
                if let Some(len) = T::binary_len(&m) {
                    metrics.record_websocket_binary_frame(transport_kind, protocol, "out", len);
                }
                T::send(&mut writer, m).await?;
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    T::finish(&mut writer).await;
    result
}
