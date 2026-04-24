use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::{Mutex, watch};
use tracing::{debug, warn};

use outline_metrics as metrics;

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{TcpFlowState, TcpFlowStatus, flush_server_output};
use super::super::super::TunTcpEngine;

impl TunTcpEngine {
    /// Simpler reader for direct (non-tunneled) TCP flows: reads raw bytes
    /// from the plain `OwnedReadHalf` and pushes them through the same TCP
    /// state machine that synthesises IP packets for the TUN device.
    pub(in crate::tcp::engine) fn spawn_direct_upstream_reader(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        mut read_half: OwnedReadHalf,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16_384];
            loop {
                let read_result = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            return;
                        }
                        continue;
                    }
                    result = read_half.read(&mut buf) => result,
                };
                match read_result {
                    Ok(0) => {
                        // EOF — upstream closed.
                        let flush = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.server_fin_pending = true;
                            let flush = flush_server_output(&mut state);
                            commit_flow_changes(&mut state, &engine.inner.tcp);
                            flush
                        };
                        match flush {
                            Ok(flush) => {
                                if engine
                                    .write_server_flush(
                                        &key,
                                        flush,
                                        metrics::DIRECT_GROUP_LABEL,
                                        metrics::DIRECT_UPLINK_LABEL,
                                    )
                                    .await
                                    .is_err()
                                {
                                    engine.close_flow(&key, "write_tun_error").await;
                                }
                            },
                            Err(_) => {
                                engine.close_flow(&key, "build_packet_error").await;
                            },
                        }
                        return;
                    },
                    Ok(n) => {
                        let chunk = Bytes::copy_from_slice(&buf[..n]);
                        let flush = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.timestamps.last_seen = Instant::now();
                            state.pending_server_data.push_back(chunk);
                            let flush = flush_server_output(&mut state);
                            commit_flow_changes(&mut state, &engine.inner.tcp);
                            flush
                        };
                        match flush {
                            Ok(flush) => {
                                if let Err(error) = engine
                                    .write_server_flush(
                                        &key,
                                        flush,
                                        metrics::DIRECT_GROUP_LABEL,
                                        metrics::DIRECT_UPLINK_LABEL,
                                    )
                                    .await
                                {
                                    warn!(error = %format!("{error:#}"), "failed to write direct TUN TCP flush");
                                    engine.close_flow(&key, "write_tun_error").await;
                                    return;
                                }
                                metrics::add_bytes(
                                    "tcp",
                                    "upstream_to_client",
                                    metrics::DIRECT_GROUP_LABEL,
                                    metrics::DIRECT_UPLINK_LABEL,
                                    n,
                                );
                            },
                            Err(error) => {
                                warn!(
                                    error = %format!("{error:#}"),
                                    "failed to flush direct TUN TCP data"
                                );
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            },
                        }
                    },
                    Err(error) => {
                        debug!(error = %format!("{error:#}"), "direct upstream TCP reader ended");
                        engine.close_flow(&key, "read_error").await;
                        return;
                    },
                }
            }
        });
    }
}
