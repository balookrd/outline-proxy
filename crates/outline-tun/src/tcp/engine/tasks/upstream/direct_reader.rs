use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::{Mutex, watch};
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_net::RelayReadBuf;

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{
    TcpFlowState, TcpFlowStatus, assess_server_backlog_pressure, flush_server_output,
};
use super::super::super::TunTcpEngine;
use super::backlog::BacklogGate;

/// Read window a direct flow offers the origin on each `try_read_buf`.
pub(in crate::tcp::engine) const DIRECT_READ_BUFFER_BYTES: usize = 16_384;

impl TunTcpEngine {
    /// Simpler reader for direct (non-tunneled) TCP flows: reads raw bytes
    /// from the plain `OwnedReadHalf` and pushes them through the same TCP
    /// state machine that synthesises IP packets for the TUN device.
    pub(in crate::tcp::engine) fn spawn_direct_upstream_reader(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        read_half: OwnedReadHalf,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        // Direct flows carry the constant `(direct, direct)` labels, so the
        // downlink byte counter is process-global — resolve it once.
        let down_bytes = metrics::direct_tcp_bytes("down");
        tokio::spawn(async move {
            // One buffer for the whole flow, the way the SOCKS relay loops do
            // it. The previous per-read `Vec::with_capacity` allocated and freed
            // 16 KiB on every readable event — thousands per second under load,
            // interleaved with the flow's long-lived structures. Heap profiling
            // found ~82% of RSS sitting in dirty mimalloc arenas that could not
            // be returned, a few long-lived objects pinning each one; churn of
            // this shape is what spreads those objects across arenas in the
            // first place, so it is worth not producing.
            //
            // `fixed`, not `adaptive`: this keeps the flat 16 KiB window the
            // flow already advertised, so only the allocation pattern changes.
            // The buffer is still dropped after `RELAY_BUF_IDLE_GRACE`, so an
            // idle direct flow pins nothing — exactly what allocating per read
            // bought us.
            let mut read_buf = RelayReadBuf::fixed(DIRECT_READ_BUFFER_BYTES);
            loop {
                // Downlink backpressure. Parking here stops draining the socket,
                // so the kernel receive buffer fills and the window we advertise
                // to the origin shrinks — throttling it at the source, the way a
                // tunnelled flow throttles the carrier via WS/QUIC stream credit.
                // Without this a fast origin feeding a slow client grew
                // `pending_server_data` without bound.
                if matches!(
                    engine.await_downlink_backlog_room(&key, &flow, &mut close_rx).await,
                    BacklogGate::Stop
                ) {
                    return;
                }

                // Waiting for readability goes through the buffer's own park —
                // that is what arms the idle release.
                let ready = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            return;
                        }
                        continue;
                    }
                    ready = read_buf.park(read_half.readable()) => ready,
                };
                if ready.is_err() {
                    engine.close_flow(&key, "read_error").await;
                    return;
                }
                let read_result = read_half.try_read_buf(read_buf.ready());
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
                        // Copied, not adopted: the buffer is reused by the
                        // next read, and the chunk outlives it in the flow's
                        // downlink queue. The copy is exactly `n` bytes, so the
                        // queue's charge and the memory it holds agree.
                        let chunk = Bytes::copy_from_slice(read_buf.filled());
                        let (flush, backlog_pressure) = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.timestamps.last_seen = Instant::now();
                            engine.record_flow_activity(&mut state);
                            state.charge_pending_server(chunk.len());
                            state.pending_server_data.push_back(chunk);
                            let flush = flush_server_output(&mut state);
                            let backlog_pressure = assess_server_backlog_pressure(
                                &mut state,
                                &engine.inner.tcp,
                                Instant::now(),
                                flush.as_ref().map(|flush| flush.window_stalled).unwrap_or(false),
                            );
                            commit_flow_changes(&mut state, &engine.inner.tcp);
                            (flush, backlog_pressure)
                        };

                        if backlog_pressure.should_abort {
                            engine.abort_tun_tcp_backlog(&key, &flow, &backlog_pressure).await;
                            return;
                        } else if backlog_pressure.exceeded {
                            debug!(
                                pending_bytes = backlog_pressure.pending_bytes,
                                limit_bytes = engine.inner.tcp.max_pending_server_bytes,
                                over_limit_ms = backlog_pressure.over_limit_ms.unwrap_or_default(),
                                no_progress_ms =
                                    backlog_pressure.no_progress_ms.unwrap_or_default(),
                                window_stalled = backlog_pressure.window_stalled,
                                "direct TUN TCP flow is under backlog pressure, delaying abort"
                            );
                        }

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
                                down_bytes.add(n);
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
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
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
