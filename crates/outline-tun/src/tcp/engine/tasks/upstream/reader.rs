use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use tokio::sync::{Mutex, watch};
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_transport::TcpReader;
use outline_uplink::TransportKind;

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{
    ServerBacklogPressure, ServerFlush, TcpFlowState, TcpFlowStatus,
    assess_server_backlog_pressure, flush_server_output, pending_server_bytes, server_fin_sent,
    server_window_stalled,
};
use super::super::super::{TunTcpEngine, key_group_and_uplink, key_uplink_name};

/// How often the downlink-backpressure pause re-evaluates the flow while it
/// waits for the client to drain. A safety re-check in case the `server_drain`
/// wake-up is missed (notify has no stored permit across iterations), and the
/// cadence at which a genuinely stalled flow's no-progress abort is observed
/// while the reader is parked and not otherwise reading.
const SERVER_BACKLOG_RECHECK_INTERVAL: Duration = Duration::from_millis(200);

impl TunTcpEngine {
    pub(in crate::tcp::engine) fn spawn_upstream_reader(
        &self,
        key: TcpFlowKey,
        flow: Arc<Mutex<TcpFlowState>>,
        mut upstream_reader: TcpReader,
        mut close_rx: watch::Receiver<bool>,
    ) {
        let engine = self.clone();
        tokio::spawn(async move {
            // Downlink byte counter, cached across reads. `key_group_and_uplink`
            // hands back ptr-stable `Arc<str>` clones for the flow's group and
            // uplink; a mid-flow failover swaps `uplink_name` for a fresh `Arc`,
            // which re-resolves the handle onto the new series (old series stops
            // growing) via the `Arc::ptr_eq` check inside `FailoverCounter`.
            let mut down_bytes = metrics::FailoverCounter::new();
            loop {
                let manager = { flow.lock().await.routing.manager.clone() };
                if manager.strict_active_uplink_for(TransportKind::Tcp) {
                    let active_uplink =
                        manager.active_uplink_index_for_transport(TransportKind::Tcp).await;
                    let should_abort = {
                        let state = flow.lock().await;
                        active_uplink.is_some_and(|active| {
                            state.routing.uplink_index != usize::MAX
                                && state.routing.uplink_index != active
                        })
                    };
                    if should_abort {
                        engine.abort_flow_with_rst(&key, "global_switch").await;
                        return;
                    }
                }

                // Downlink backpressure: while the per-flow downlink buffer is
                // over the soft limit, stop draining the carrier and wait for
                // the client to ACK and make room. Not reading lets the WS/QUIC
                // stream flow-control throttle the server, so a slow client no
                // longer grows `pending_server_data` into the hard-limit RST
                // that tore down healthy large downloads. A genuinely stalled
                // client (window shut, no ACK progress) is still reaped here.
                loop {
                    let (over_limit, pressure, drain) = {
                        let mut state = flow.lock().await;
                        if matches!(state.status, TcpFlowStatus::Closed) {
                            return;
                        }
                        let drain = state.signals.server_drain.clone();
                        if pending_server_bytes(&state) <= engine.inner.tcp.max_pending_server_bytes
                        {
                            (false, None, drain)
                        } else {
                            let stalled = server_window_stalled(&state);
                            let pressure = assess_server_backlog_pressure(
                                &mut state,
                                &engine.inner.tcp,
                                Instant::now(),
                                stalled,
                            );
                            commit_flow_changes(&mut state, &engine.inner.tcp);
                            (true, Some(pressure), drain)
                        }
                    };
                    if !over_limit {
                        break;
                    }
                    if let Some(pressure) = pressure
                        && pressure.should_abort
                    {
                        engine.abort_tun_tcp_backlog(&key, &flow, &pressure).await;
                        return;
                    }
                    tokio::select! {
                        _ = close_rx.changed() => {
                            if *close_rx.borrow() {
                                debug!("upstream TCP flow reader cancelled");
                                return;
                            }
                        }
                        _ = drain.notified() => {}
                        _ = tokio::time::sleep(SERVER_BACKLOG_RECHECK_INTERVAL) => {}
                    }
                }

                let read_result = tokio::select! {
                    _ = close_rx.changed() => {
                        if *close_rx.borrow() {
                            debug!("upstream TCP flow reader cancelled");
                            return;
                        }
                        continue;
                    }
                    result = upstream_reader.read_chunk() => result,
                };
                match read_result {
                    Ok(chunk) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        let chunk_len = chunk.len();
                        let (flush, backlog_pressure, uplink_name) = {
                            let mut state = flow.lock().await;
                            if matches!(state.status, TcpFlowStatus::Closed) {
                                return;
                            }
                            state.timestamps.last_seen = Instant::now();
                            engine.record_flow_activity(&state);
                            state.pending_server_bytes_total += chunk.len();
                            state.pending_server_data.push_back(chunk);
                            let flush = flush_server_output(&mut state);
                            let backlog_pressure = assess_server_backlog_pressure(
                                &mut state,
                                &engine.inner.tcp,
                                Instant::now(),
                                flush.as_ref().map(|flush| flush.window_stalled).unwrap_or(false),
                            );
                            commit_flow_changes(&mut state, &engine.inner.tcp);
                            (flush, backlog_pressure, state.routing.uplink_name.clone())
                        };

                        if backlog_pressure.should_abort {
                            engine.abort_tun_tcp_backlog(&key, &flow, &backlog_pressure).await;
                            return;
                        } else if backlog_pressure.exceeded {
                            debug!(
                                uplink = %uplink_name,
                                pending_bytes = backlog_pressure.pending_bytes,
                                limit_bytes = engine.inner.tcp.max_pending_server_bytes,
                                over_limit_ms = backlog_pressure.over_limit_ms.unwrap_or_default(),
                                no_progress_ms = backlog_pressure.no_progress_ms.unwrap_or_default(),
                                window_stalled = backlog_pressure.window_stalled,
                                "TUN TCP flow is under backlog pressure, delaying abort"
                            );
                        }

                        match flush {
                            Ok(flush) => {
                                let (group_name, uplink_name) = key_group_and_uplink(&flow).await;
                                if let Err(error) = engine
                                    .write_server_flush(&key, flush, &group_name, &uplink_name)
                                    .await
                                {
                                    warn!(error = %format!("{error:#}"), "failed to write TUN TCP flush");
                                    engine.close_flow(&key, "write_tun_error").await;
                                    return;
                                }
                                down_bytes
                                    .get(&group_name, &uplink_name, |group, uplink| {
                                        metrics::flow_bytes_counter("tcp", "down", group, uplink)
                                    })
                                    .add(chunk_len);
                            },
                            Err(error) => {
                                warn!(error = %format!("{error:#}"), "failed to build TUN TCP data packet");
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            },
                        }
                    },
                    Err(error) => {
                        // Transport errors (e.g. QUIC APPLICATION_CLOSE /
                        // H3_INTERNAL_ERROR) set closed_cleanly=false.  Report
                        // them as uplink runtime failures so the penalty system
                        // can switch to a backup uplink or fall back to H2/H1.
                        // Clean WebSocket closes (FIN, Close frame) do not
                        // indicate an uplink problem and are not reported.
                        if !upstream_reader.closed_cleanly() {
                            let (uplink_index, flow_manager) = {
                                let state = flow.lock().await;
                                (state.routing.uplink_index, state.routing.manager.clone())
                            };
                            if crate::error_classify::is_ws_closed(&error) {
                                flow_manager
                                    .report_upstream_close(uplink_index, TransportKind::Tcp)
                                    .await;
                            } else {
                                engine
                                    .report_tcp_runtime_failure(&flow_manager, uplink_index, &error)
                                    .await;
                            }
                        }
                        debug!(error = %format!("{error:#}"), "upstream TCP flow reader ended");
                        let flush = {
                            let mut state = flow.lock().await;
                            if state.status == TcpFlowStatus::Closed
                                || server_fin_sent(state.status)
                            {
                                Ok(ServerFlush::default())
                            } else {
                                state.server_fin_pending = true;
                                let flush = flush_server_output(&mut state);
                                commit_flow_changes(&mut state, &engine.inner.tcp);
                                flush
                            }
                        };

                        match flush {
                            Ok(flush) => {
                                let (group_name, uplink_name) = key_group_and_uplink(&flow).await;
                                if let Err(write_error) = engine
                                    .write_server_flush(&key, flush, &group_name, &uplink_name)
                                    .await
                                {
                                    warn!(error = %format!("{write_error:#}"), "failed to write deferred TUN TCP FIN/data");
                                    engine.close_flow(&key, "write_tun_error").await;
                                    return;
                                }
                            },
                            Err(flush_error) => {
                                warn!(error = %format!("{flush_error:#}"), "failed to flush deferred server FIN/data");
                                engine.close_flow(&key, "build_packet_error").await;
                                return;
                            },
                        }

                        let should_close = {
                            let state = flow.lock().await;
                            state.status == TcpFlowStatus::Closed
                        };
                        if should_close {
                            engine.close_flow(&key, "upstream_closed").await;
                        }
                        return;
                    },
                }
            }
        });
    }

    /// Tear down a TUN TCP flow whose downlink buffer hit the backlog abort
    /// condition: report the uplink runtime failure (so the penalty system can
    /// fail over), log the diagnostic snapshot, and RST the flow. Shared by the
    /// backpressure-pause path and the post-read assessment so both emit an
    /// identical failure signal.
    async fn abort_tun_tcp_backlog(
        &self,
        key: &TcpFlowKey,
        flow: &Arc<Mutex<TcpFlowState>>,
        pressure: &ServerBacklogPressure,
    ) {
        let uplink_name = key_uplink_name(flow).await;
        let (uplink_index, flow_manager) = {
            let state = flow.lock().await;
            (state.routing.uplink_index, state.routing.manager.clone())
        };
        let error = anyhow!("server backlog limit exceeded for TUN TCP flow");
        self.report_tcp_runtime_failure(&flow_manager, uplink_index, &error)
            .await;
        let (cooldown_ms, penalty_ms) = flow_manager
            .runtime_failure_debug_state(uplink_index, TransportKind::Tcp)
            .await;
        warn!(
            uplink = %uplink_name,
            uplink_index,
            cooldown_ms,
            penalty_ms,
            pending_bytes = pressure.pending_bytes,
            limit_bytes = self.inner.tcp.max_pending_server_bytes,
            grace_ms = pressure.over_limit_ms.unwrap_or_default(),
            no_progress_ms = pressure.no_progress_ms.unwrap_or_default(),
            "closing TUN TCP flow after server backlog limit"
        );
        self.abort_flow_with_rst(key, "server_backlog_limit").await;
    }
}
