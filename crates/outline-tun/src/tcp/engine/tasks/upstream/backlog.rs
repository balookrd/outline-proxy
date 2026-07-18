use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use tokio::sync::{Mutex, watch};
use tokio::time::sleep;
use tracing::{debug, warn};

use outline_metrics as metrics;
use outline_uplink::TransportKind;

use super::super::super::super::TcpFlowKey;
use super::super::super::super::maintenance::commit_flow_changes;
use super::super::super::super::state_machine::{
    ServerBacklogPressure, TcpFlowState, TcpFlowStatus, assess_server_backlog_pressure,
    pending_server_bytes, server_window_stalled,
};
use super::super::super::{TunTcpEngine, key_uplink_name};

/// How often the downlink-backpressure pause re-evaluates the flow while it
/// waits for the client to drain. A safety re-check in case the `server_drain`
/// wake-up is missed (notify has no stored permit across iterations), and the
/// cadence at which a genuinely stalled flow's no-progress abort is observed
/// while the reader is parked and not otherwise reading.
const SERVER_BACKLOG_RECHECK_INTERVAL: Duration = Duration::from_millis(200);

/// Outcome of the downlink-backpressure gate.
pub(super) enum BacklogGate {
    /// The downlink buffer has room — go read.
    Proceed,
    /// The flow is gone (closed, cancelled, or reaped for a stalled backlog):
    /// the caller must return without reading.
    Stop,
}

/// One lock-scoped assessment of the gate: why (if at all) the reader must
/// park this iteration.
enum GateVerdict {
    /// Neither the per-flow limit nor the global budget is exceeded.
    Room,
    /// This flow's own buffer is over `max_pending_server_bytes` — the
    /// existing per-flow backpressure, with its stall-abort escalation.
    FlowOver(ServerBacklogPressure),
    /// The flow is fine but the engine-wide pending-downlink sum is over
    /// `pending_server_budget_bytes`. Park without any abort escalation:
    /// the overload is collective, not this flow's fault, and the budget
    /// drains as clients ACK. Carries the labels for the one-shot metric.
    BudgetOver { group: Arc<str>, uplink: Arc<str>, global_bytes: usize },
}

impl TunTcpEngine {
    /// Park while the per-flow downlink buffer sits over the soft limit — or
    /// while the engine-wide pending-downlink sum sits over the global budget —
    /// so the reader stops draining its upstream and lets flow control push
    /// back on the origin instead of buffering for it.
    ///
    /// The push-back differs per path but the intent is identical: on a tunnelled
    /// flow, not reading lets WS/QUIC stream credit throttle the server; on a
    /// direct flow it lets the kernel receive buffer fill, shrinking the window
    /// we advertise to the origin. Either way a slow client can no longer grow
    /// `pending_server_data` without bound. A *genuinely* stalled client (window
    /// shut, no ACK progress) is still reaped here rather than buffered forever.
    ///
    /// The global-budget park (`pending_server_budget_bytes`) has no abort
    /// escalation: it stops *every* reader at once when the host-wide sum runs
    /// away (a burst of concurrent bulk downloads on a low-RAM host), and
    /// releases them as client ACKs drain the queues. A flow whose own client
    /// is dead still falls to its usual keepalive / idle / no-progress reaping,
    /// which returns its share of the budget via `TcpFlowState::drop`.
    pub(super) async fn await_downlink_backlog_room(
        &self,
        key: &TcpFlowKey,
        flow: &Arc<Mutex<TcpFlowState>>,
        close_rx: &mut watch::Receiver<bool>,
    ) -> BacklogGate {
        let budget = self.inner.tcp.pending_server_budget_bytes;
        let mut budget_park_reported = false;
        loop {
            let (verdict, drain) = {
                let mut state = flow.lock().await;
                if matches!(state.status, TcpFlowStatus::Closed) {
                    return BacklogGate::Stop;
                }
                let drain = state.signals.server_drain.clone();
                if pending_server_bytes(&state) > self.inner.tcp.max_pending_server_bytes {
                    let stalled = server_window_stalled(&state);
                    let pressure = assess_server_backlog_pressure(
                        &mut state,
                        &self.inner.tcp,
                        Instant::now(),
                        stalled,
                    );
                    commit_flow_changes(&mut state, &self.inner.tcp);
                    (GateVerdict::FlowOver(pressure), drain)
                } else {
                    let global_bytes = self
                        .inner
                        .pending_server_bytes_global
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if budget > 0 && global_bytes > budget {
                        let verdict = GateVerdict::BudgetOver {
                            group: state.routing.group_name.clone(),
                            uplink: state.routing.uplink_name.clone(),
                            global_bytes,
                        };
                        (verdict, drain)
                    } else {
                        (GateVerdict::Room, drain)
                    }
                }
            };
            match verdict {
                GateVerdict::Room => return BacklogGate::Proceed,
                GateVerdict::FlowOver(pressure) => {
                    if pressure.should_abort {
                        self.abort_tun_tcp_backlog(key, flow, &pressure).await;
                        return BacklogGate::Stop;
                    }
                },
                GateVerdict::BudgetOver { group, uplink, global_bytes } => {
                    // Report once per park episode, not per 200 ms recheck.
                    if !budget_park_reported {
                        budget_park_reported = true;
                        metrics::record_tun_tcp_event(&group, &uplink, "budget_parked");
                        debug!(
                            global_pending_bytes = global_bytes,
                            budget_bytes = budget,
                            "TUN TCP reader parked: engine-wide pending downlink budget exceeded"
                        );
                    }
                },
            }
            tokio::select! {
                _ = close_rx.changed() => {
                    if *close_rx.borrow() {
                        debug!("upstream TCP flow reader cancelled");
                        return BacklogGate::Stop;
                    }
                }
                _ = drain.notified() => {}
                _ = sleep(SERVER_BACKLOG_RECHECK_INTERVAL) => {}
            }
        }
    }

    /// Tear down a TUN TCP flow whose downlink buffer hit the backlog abort
    /// condition: report the uplink runtime failure (so the penalty system can
    /// fail over), log the diagnostic snapshot, and RST the flow. Shared by the
    /// backpressure pause, the post-read assessment, and both readers, so every
    /// path emits an identical failure signal.
    ///
    /// A direct flow carries `uplink_index == usize::MAX`: there is no uplink to
    /// penalise, so the failure report is a no-op and the penalty fields are
    /// absent from the log rather than printed as a sentinel.
    pub(super) async fn abort_tun_tcp_backlog(
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
        let uplink_index = (uplink_index != usize::MAX).then_some(uplink_index);
        warn!(
            uplink = %uplink_name,
            ?uplink_index,
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
