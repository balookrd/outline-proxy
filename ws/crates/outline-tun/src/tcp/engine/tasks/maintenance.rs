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

                    // Filter stale heap entries: if the flow's canonical
                    // deadline has moved (either re-scheduled earlier and
                    // this is an orphan, or later and we're too early),
                    // skip. The canonical entry will fire on its own.
                    match state.next_scheduled_deadline {
                        Some(d) if d == scheduled_at => {},
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
                                if let Err(error) =
                                    engine.inner.writer.write_packet(&packet).await
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
                                metrics::record_tun_tcp_event(
                                    &group_name,
                                    &uplink_name,
                                    event,
                                );
                                metrics::record_tun_packet(
                                    "upstream_to_tun",
                                    ip_family,
                                    packet_metric,
                                );
                                // Re-acquire lock to process the next action for
                                // this flow (e.g., back-to-back retransmissions).
                                state = flow.lock().await;
                            },
                            Err(error) => {
                                warn!(
                                    error = %format!("{error:#}"),
                                    "failed to plan TUN TCP flow maintenance"
                                );
                                drop(state);
                                engine
                                    .abort_flow_with_rst(&key, "retransmit_build_error")
                                    .await;
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
