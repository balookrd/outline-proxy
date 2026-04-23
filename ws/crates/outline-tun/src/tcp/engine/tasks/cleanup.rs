use std::time::Instant;

use tokio::time::sleep;
use tracing::debug;

use super::super::super::TcpFlowKey;
use super::super::super::state_machine::TcpFlowStatus;
use super::super::TunTcpEngine;

impl TunTcpEngine {
    /// Watchdog GC loop: periodically scans the flow table for flows whose
    /// `last_seen` is older than `idle_timeout`, and aborts them. The
    /// per-flow `spawn_flow_maintenance` task is the primary idle-cleanup
    /// path — this loop is a safety net against maintenance tasks that
    /// panic or exit without removing the flow from the table.
    pub(in crate::tcp::engine) fn spawn_cleanup_loop(&self) {
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(super::super::super::TUN_TCP_FLOW_CLEANUP_INTERVAL).await;
                engine.cleanup_idle_flows().await;
            }
        });
    }

    async fn cleanup_idle_flows(&self) {
        let now = Instant::now();
        let idle_timeout = self.inner.idle_timeout;

        // Iterate the map directly and inspect each flow under `try_lock`:
        // avoids the O(flows) snapshot allocation and never holds an async
        // lock across a DashMap shard guard. A flow currently held by
        // another task is skipped — the GC is a safety net, so we'll
        // revisit it on the next tick.
        let mut expired: Vec<TcpFlowKey> = Vec::new();
        for entry in self.inner.flows.iter() {
            let Ok(state) = entry.value().try_lock() else {
                continue;
            };
            if matches!(state.status, TcpFlowStatus::Closed) {
                expired.push(entry.key().clone());
                continue;
            }
            // TimeWait uses its own timeout handled by per-flow
            // maintenance; only hit TimeWait here if it wildly overran.
            if state.status == TcpFlowStatus::TimeWait {
                if now.saturating_duration_since(state.timestamps.status_since)
                    >= super::super::super::TCP_TIME_WAIT_TIMEOUT + idle_timeout
                {
                    expired.push(entry.key().clone());
                }
                continue;
            }
            if now.saturating_duration_since(state.timestamps.last_seen) >= idle_timeout {
                expired.push(entry.key().clone());
            }
        }

        if expired.is_empty() {
            return;
        }
        let count = expired.len();
        for key in expired {
            self.abort_flow_with_rst(&key, "idle_gc").await;
        }
        debug!(count, "TUN TCP GC: reaped idle flows");
    }
}
