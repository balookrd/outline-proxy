use std::time::Instant;

use tokio::time::sleep;
use tracing::debug;

use super::super::super::TcpFlowKey;
use super::super::super::state_machine::{TcpFlowStatus, reclaim_flow_queue_capacity};
use super::super::TunTcpEngine;

impl TunTcpEngine {
    /// Watchdog GC loop: periodically scans the flow table for flows whose
    /// `last_seen` is older than `idle_timeout`, and aborts them. The
    /// per-flow `spawn_flow_maintenance` task is the primary idle-cleanup
    /// path — this loop is a safety net against maintenance tasks that
    /// panic or exit without removing the flow from the table.
    ///
    /// It doubles as the periodic per-flow visit that reclaims the queue
    /// capacity a finished transfer left behind ([`reclaim_flow_queue_capacity`]):
    /// the deadline-driven maintenance loop never revisits a quiet flow until
    /// its idle timeout, so this tick is the only place that can hand the
    /// allocation back while the flow is still alive.
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
            let Ok(mut state) = entry.value().try_lock() else {
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
            let quiet_for = now.saturating_duration_since(state.timestamps.last_seen);
            if quiet_for >= idle_timeout {
                expired.push(entry.key().clone());
                continue;
            }
            // The flow survives — hand back the queue capacity its last transfer
            // grew to, once it has been quiet long enough that shrinking will not
            // just be undone by the next chunk.
            if quiet_for >= super::super::super::TCP_QUEUE_RECLAIM_IDLE {
                reclaim_flow_queue_capacity(&mut state);
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
