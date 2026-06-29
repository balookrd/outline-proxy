use std::sync::Arc;

use tokio::sync::{Mutex, Notify, watch};

use outline_metrics as metrics;
use outline_uplink::UplinkManager;

use super::super::super::super::state_machine::{
    TcpFlowState, TcpFlowStatus, UpstreamWriter, advertised_receive_window, build_flow_ack_packet,
    client_fin_seen,
};
use super::super::super::super::{TCP_FLAG_ACK, TcpFlowKey};
use super::super::super::{TunTcpEngine, close_upstream_writer};

impl TunTcpEngine {
    /// Per-flow upstream pump: the sole writer to `upstream_writer` once a
    /// flow is connected. It drains `pending_client_data` (filled by the
    /// shared TUN read-loop) into the upstream and parks on the bounded
    /// upstream channel when it back-pressures.
    ///
    /// This is what decouples the read-loop from per-flow upstream
    /// back-pressure: the read-loop only appends to the buffer and wakes
    /// this task, so a slow/degraded uplink stalls one flow's pump instead
    /// of head-of-line-blocking the single read-loop (and with it every
    /// other flow and local service riding the TUN). Back-pressure still
    /// reaches the client honestly — the buffer counts toward
    /// `buffered_client_bytes`, which shrinks the advertised receive window.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::tcp::engine) fn spawn_upstream_pump(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        upstream_writer: Arc<Mutex<UpstreamWriter>>,
        manager: UplinkManager,
        uplink_index: usize,
        group_name: Arc<str>,
        uplink_name: Arc<str>,
        notify: Arc<Notify>,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                // Snapshot whether we are currently advertising a *closed*
                // receive window. If so the client has stalled its uplink: the
                // drain below shrinks `buffered_client_bytes` and reopens the
                // window, but without an explicit update the client only learns
                // of it via its own zero-window probe — whose backoff grows and
                // throttles uplink throughput to a fraction of the link. We send
                // a proactive window update after draining to wake it at once.
                let window_was_closed = {
                    let state = flow.lock().await;
                    if matches!(state.status, TcpFlowStatus::Closed) {
                        return;
                    }
                    advertised_receive_window(&state) == 0
                };

                // Drain everything currently buffered, in order. Popping
                // under the flow lock and being the only writer keeps the
                // upstream byte stream correctly ordered.
                loop {
                    let payload = {
                        let mut state = flow.lock().await;
                        if matches!(state.status, TcpFlowStatus::Closed) {
                            return;
                        }
                        state.pending_client_data.pop_front()
                    };
                    let Some(payload) = payload else { break };
                    let send_result = {
                        let mut writer = upstream_writer.lock().await;
                        writer.send_chunk(&payload).await
                    };
                    if let Err(error) = send_result {
                        engine
                            .report_tcp_runtime_failure_and_abort(
                                &key,
                                &manager,
                                uplink_index,
                                &error,
                                "send_error",
                            )
                            .await;
                        return;
                    }
                    metrics::add_bytes(
                        "tcp",
                        "client_to_upstream",
                        &group_name,
                        &uplink_name,
                        payload.len(),
                    );
                }

                // Buffer drained. If the client half-closed, the flush is
                // complete — close the upstream write half and finish. Doing
                // this here (not in the read-loop) guarantees the FIN never
                // races ahead of still-buffered payload.
                {
                    let state = flow.lock().await;
                    if client_fin_seen(state.status) {
                        drop(state);
                        close_upstream_writer(Some(upstream_writer)).await;
                        return;
                    }
                }

                // Proactive window update: if we had advertised a closed window
                // and the drain reopened it, tell the client now instead of
                // waiting for its (back-off-delayed) zero-window probe.
                if window_was_closed {
                    let ack = {
                        let state = flow.lock().await;
                        if !matches!(state.status, TcpFlowStatus::Closed)
                            && advertised_receive_window(&state) > 0
                        {
                            build_flow_ack_packet(
                                &state,
                                state.server_seq,
                                state.rcv_nxt,
                                TCP_FLAG_ACK,
                            )
                            .ok()
                        } else {
                            None
                        }
                    };
                    if let Some(ack) = ack {
                        let _ = engine.inner.writer.write_packet(&ack).await;
                    }
                }

                // Park until the read-loop buffers more data or the flow is
                // torn down. A `notify_one` issued between the drain above
                // and this await is preserved as a permit, so no wakeup is
                // lost; `close_rx` covers abort / migration / FIN-from-peer.
                tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            return;
                        }
                    }
                    _ = notify.notified() => {}
                }
            }
        });
    }
}
