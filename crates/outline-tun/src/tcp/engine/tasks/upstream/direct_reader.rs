use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::{Mutex, watch};
use tracing::{debug, warn};

use outline_metrics as metrics;

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{
    TcpFlowState, TcpFlowStatus, assess_server_backlog_pressure, flush_server_output,
};
use super::super::super::TunTcpEngine;
use super::backlog::BacklogGate;

/// Read buffer handed to one `try_read_buf` call.
pub(in crate::tcp::engine) const DIRECT_READ_BUFFER_BYTES: usize = 16_384;

/// How far the buffer may outweigh the bytes actually read before the chunk is
/// copied into a right-sized allocation.
///
/// `Bytes::from(Vec)` adopts the whole allocation, so a chunk keeps the entire
/// read buffer alive for as long as it sits in the flow's downlink queue — a
/// 100-byte read pinning 16 KiB. The queue is charged `chunk.len()`, so the
/// engine-wide `pending_server_budget_bytes` counted the 100 bytes and stayed
/// blind to the 16 KiB actually held: the budget could be overrun manyfold
/// while reporting itself nearly empty.
///
/// Copying is only worth it while the waste dominates: at a nearly-full buffer
/// the copy costs about as many bytes as it frees, so the chunk is handed over
/// as-is. Interactive traffic — the case that produced 100-byte reads — sits far
/// below this ratio and is always compacted.
const COMPACT_WHEN_CAPACITY_EXCEEDS_FILLED_BY: usize = 2;

/// Whether a read of `filled` bytes into a buffer of `capacity` should be copied
/// into a right-sized allocation instead of adopting the buffer wholesale.
pub(in crate::tcp::engine) fn should_compact_read_chunk(filled: usize, capacity: usize) -> bool {
    filled > 0 && filled.saturating_mul(COMPACT_WHEN_CAPACITY_EXCEEDS_FILLED_BY) < capacity
}

/// Turns a read buffer into the chunk queued for the client, copying it down to
/// size when the buffer would otherwise be pinned by a fraction of its bytes.
pub(in crate::tcp::engine) fn compact_read_chunk(mut buf: Vec<u8>, filled: usize) -> Bytes {
    let filled = filled.min(buf.len());
    if should_compact_read_chunk(filled, buf.capacity()) {
        return Bytes::copy_from_slice(&buf[..filled]);
    }
    buf.truncate(filled);
    Bytes::from(buf)
}

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

                // Wait for readability (or close) without holding a receive
                // buffer; allocate it only once data is ready and drop it
                // before the next park, so an idle direct flow holds no
                // per-flow read buffer.
                let ready = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            return;
                        }
                        continue;
                    }
                    ready = read_half.readable() => ready,
                };
                if ready.is_err() {
                    engine.close_flow(&key, "read_error").await;
                    return;
                }
                let mut buf = Vec::with_capacity(DIRECT_READ_BUFFER_BYTES);
                let read_result = read_half.try_read_buf(&mut buf);
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
                        let chunk = compact_read_chunk(buf, n);
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
