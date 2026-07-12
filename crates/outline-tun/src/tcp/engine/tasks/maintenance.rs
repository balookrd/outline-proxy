use std::sync::Arc;
use std::time::Instant;

use tokio::time::sleep_until;
use tracing::warn;

use outline_metrics as metrics;

use super::super::super::maintenance::{FlowMaintenancePlan, plan_flow_maintenance};
use super::super::super::state_machine::TcpFlowStatus;
use super::super::{TunTcpEngine, ip_family_from_version};

impl TunTcpEngine {
    /// Single engine-wide maintenance task driven by `FlowScheduler`:
    /// every state mutation (`commit_flow_changes`) pushes the
    /// flow's next deadline onto a priority queue. This loop pops entries
    /// in deadline order, runs `plan_flow_maintenance`, and sleeps until
    /// the next one. Stale pushes are filtered by matching the popped
    /// deadline against `state.next_scheduled_deadline`.
    ///
    /// Lock contention is rare and brief (holders don't await inside the
    /// critical section), so `.lock().await` is preferred over `try_lock`
    /// + retry — it avoids busy-looping a contended flow at 1ms cadence.
    pub(in crate::tcp::engine) fn spawn_maintenance_loop(&self) {
        let engine = self.clone();
        tokio::spawn(async move {
            let scheduler = Arc::clone(&engine.inner.scheduler);
            loop {
                let now = Instant::now();
                let due = scheduler.drain_due(now);

                'flows: for (scheduled_at, key) in due {
                    let Some(flow) = engine.lookup_flow(&key).await else {
                        continue;
                    };
                    let mut state = flow.lock().await;

                    // Filter heap entries against the flow's canonical
                    // deadline. Process an entry that fires at or before the
                    // canonical deadline (`scheduled_at <= d`): the exact match
                    // is the canonical wake-up, and an *earlier* entry re-plans
                    // harmlessly (it just re-`Wait`s). Processing the earlier
                    // one is essential, because `reschedule_flow` does NOT push
                    // a heap entry when the deadline moves *later* (it only
                    // `wake()`s) — e.g. a partial ACK that clears the oldest
                    // unacked segment pushes the RTO deadline out to the next
                    // segment's later `last_sent`. Without processing the
                    // earlier (now-stale) entry, the later canonical deadline
                    // would have no heap entry at all, the flow would fall off
                    // the scheduler, and its RTO retransmit would never fire —
                    // stalling a flow that lost a non-oldest segment (a small
                    // TLS handshake whose tail is dropped on the last mile) until
                    // the peer gives up. Re-planning the early entry re-arms the
                    // canonical deadline via the `Wait` arm below. Skip only a
                    // true orphan firing *after* the canonical deadline: a later
                    // earlier-move already pushed the canonical entry.
                    match state.next_scheduled_deadline {
                        Some(d) if scheduled_at <= d => {},
                        Some(_) | None => continue 'flows,
                    }

                    // Inner loop: keep processing this flow until it asks to Wait.
                    loop {
                        if state.status == TcpFlowStatus::Closed {
                            state.next_scheduled_deadline = None;
                            break;
                        }

                        let idle_timeout = state.signals.idle_timeout;
                        let plan = plan_flow_maintenance(
                            &mut state,
                            &engine.inner.tcp,
                            idle_timeout,
                            Instant::now(),
                        );

                        match plan {
                            Ok(FlowMaintenancePlan::Wait(deadline)) => {
                                state.next_scheduled_deadline = deadline;
                                if let Some(d) = deadline {
                                    scheduler.schedule(key.clone(), d);
                                }
                                break;
                            },
                            Ok(FlowMaintenancePlan::Abort(reason)) => {
                                drop(state);
                                engine.abort_flow_with_rst(&key, reason).await;
                                continue 'flows;
                            },
                            Ok(FlowMaintenancePlan::Close(reason)) => {
                                drop(state);
                                engine.close_flow(&key, reason).await;
                                continue 'flows;
                            },
                            Ok(FlowMaintenancePlan::SendPacket {
                                packet,
                                packet_metric,
                                event,
                            }) => {
                                let ip_family = ip_family_from_version(key.version);
                                drop(state);
                                if let Err(error) = engine.inner.writer.write_packet(&packet).await
                                {
                                    warn!(
                                        error = %format!("{error:#}"),
                                        "failed to write maintenance TUN TCP packet"
                                    );
                                    engine.close_flow(&key, "write_tun_error").await;
                                    continue 'flows;
                                }
                                let (group_name, uplink_name) =
                                    super::super::key_group_and_uplink(&flow).await;
                                metrics::record_tun_tcp_event(&group_name, &uplink_name, event);
                                metrics::record_tun_packet("down", ip_family, packet_metric);
                                // Re-acquire lock to process the next action for
                                // this flow (e.g., back-to-back retransmissions).
                                state = flow.lock().await;
                            },
                            Ok(FlowMaintenancePlan::SendDataPacket {
                                packet,
                                packet_metric,
                                event,
                            }) => {
                                let ip_family = ip_family_from_version(key.version);
                                drop(state);
                                if let Err(error) = engine
                                    .inner
                                    .writer
                                    .write_data_packet(&packet.header, &packet.payload, packet.vnet)
                                    .await
                                {
                                    warn!(
                                        error = %format!("{error:#}"),
                                        "failed to write maintenance TUN TCP packet"
                                    );
                                    engine.close_flow(&key, "write_tun_error").await;
                                    continue 'flows;
                                }
                                let (group_name, uplink_name) =
                                    super::super::key_group_and_uplink(&flow).await;
                                metrics::record_tun_tcp_event(&group_name, &uplink_name, event);
                                metrics::record_tun_packet("down", ip_family, packet_metric);
                                // Re-acquire lock to process the next action for
                                // this flow (e.g., back-to-back retransmissions).
                                state = flow.lock().await;
                            },
                            Ok(FlowMaintenancePlan::FlushServer(flush)) => {
                                // BBR pacer released credit for queued downlink
                                // data; ship it like the inbound path does.
                                let server_drain = state.signals.server_drain.clone();
                                let drained = !flush.data_packets.is_empty();
                                drop(state);
                                let (group_name, uplink_name) =
                                    super::super::key_group_and_uplink(&flow).await;
                                if let Err(error) = engine
                                    .write_server_flush(&key, flush, &group_name, &uplink_name)
                                    .await
                                {
                                    warn!(
                                        error = %format!("{error:#}"),
                                        "failed to write paced server flush"
                                    );
                                    engine.close_flow(&key, "write_tun_error").await;
                                    continue 'flows;
                                }
                                // Draining `pending_server_data` may have freed
                                // room under the downlink backpressure limit;
                                // wake the reader in case it is parked.
                                if drained {
                                    server_drain.notify_one();
                                }
                                // Re-acquire to re-plan (pacing may have re-armed
                                // for the next batch, or the flow is now idle).
                                state = flow.lock().await;
                            },
                            Err(error) => {
                                warn!(
                                    error = %format!("{error:#}"),
                                    "failed to plan TUN TCP flow maintenance"
                                );
                                drop(state);
                                engine.abort_flow_with_rst(&key, "retransmit_build_error").await;
                                continue 'flows;
                            },
                        }
                    }
                }

                match scheduler.peek_deadline() {
                    Some(d) if d > Instant::now() => {
                        tokio::select! {
                            _ = scheduler.wait() => {}
                            _ = sleep_until(tokio::time::Instant::from_std(d)) => {}
                        }
                    },
                    Some(_) => tokio::task::yield_now().await,
                    None => scheduler.wait().await,
                }
            }
        });
    }
}
