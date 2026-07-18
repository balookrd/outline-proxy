use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{Mutex, watch};
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_transport::TcpReader;
use outline_uplink::TransportKind;

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{
    ServerFlush, TcpFlowState, TcpFlowStatus, assess_server_backlog_pressure, flush_server_output,
    server_fin_sent,
};
use super::super::super::{TunTcpEngine, key_group_and_uplink};
use super::backlog::BacklogGate;
use super::migrate::MigrationOutcome;

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

                if matches!(
                    engine.await_downlink_backlog_room(&key, &flow, &mut close_rx).await,
                    BacklogGate::Stop
                ) {
                    return;
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
                            engine.record_flow_activity(&mut state);
                            state.charge_pending_server(chunk.len());
                            // v2 `X-Outline-Resume-Down-Acked` accounting: the
                            // flow has *accepted* these bytes the moment they land
                            // in its downlink buffer — from here our own TCP state
                            // machine owns delivering (and retransmitting) them to
                            // the TUN client, so a resume must never ask the server
                            // to replay them again. Counting at the client's ACK
                            // instead would make the server re-send bytes we
                            // already hold. Recording only; no redial reads it yet.
                            state.resume.record_downlink_payload(chunk.len());
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
                        let carrier_died = !upstream_reader.closed_cleanly();
                        if carrier_died {
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

                        // The carrier died under a flow that was working. The
                        // server still holds this flow's upstream, parked under
                        // the Session ID it minted for it — so try to re-attach it
                        // on a fresh carrier and carry on, rather than handing the
                        // application a disconnect it never had to see.
                        //
                        // Only a *dirty* death qualifies: a clean close is the
                        // server telling us the upstream itself reached EOF, which
                        // is a real FIN and must stay one. And migration happens
                        // only on a confirmed resume hit — anything less falls
                        // through to the teardown below, unchanged. See
                        // `migrate.rs`.
                        if carrier_died
                            && let MigrationOutcome::Migrated(fresh_reader) =
                                engine.try_migrate_carrier(&key, &flow).await
                        {
                            upstream_reader = *fresh_reader;
                            continue;
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
}
