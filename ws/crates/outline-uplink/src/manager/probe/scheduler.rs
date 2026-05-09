use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep};
use tracing::{debug, warn};

use crate::config::{ProbeConfig, TransportMode};

use super::super::super::probe::probe_uplink;
use super::super::super::selection::cooldown_active;
use super::super::super::types::{TransportKind, Uplink, UplinkManager};
use super::super::status::UplinkStatus;
use super::outcome::ProbeOutcome;
use super::warm_tcp::WarmTcpProbeSlot;
use super::warm_udp::WarmUdpProbeSlot;

pub(super) fn should_skip_probe_cycle_for_recent_activity(
    status: &UplinkStatus,
    now: Instant,
    interval: Duration,
    chunk0_failure_window: Duration,
    liveness_interval: Duration,
) -> bool {
    let tcp_active = status
        .tcp
        .last_active
        .is_some_and(|t| now.duration_since(t) < interval);
    let tcp_currently_healthy = status.tcp.healthy == Some(true);
    let tcp_no_cooldown = !cooldown_active(status, TransportKind::Tcp, now);
    // Override 1 — chunk-0 freshness: do not skip the cycle when a chunk-0
    // timeout was observed recently, even if real traffic is otherwise
    // flowing through the uplink. Rescued user-flows (failover_step
    // recovers chunk-0 stalls by handing off to a fallback wire) keep
    // `last_active` fresh, so the activity check would silence the probe
    // right when its signal matters most — exactly during a chunk-0
    // storm. Probing while the signal is fresh is what lets
    // `runtime_health_escalation` / `health_effective` catch up and
    // surface the symptom on the dashboard.
    let chunk0_signal_fresh = !chunk0_failure_window.is_zero()
        && (status
            .tcp
            .last_chunk0_failure_at
            .is_some_and(|t| now.saturating_duration_since(t) < chunk0_failure_window)
            || status.tcp.chunk0_consecutive_failures > 0);
    if chunk0_signal_fresh {
        return false;
    }
    // Override 2 — liveness: even on a perfectly healthy active uplink,
    // run the probe at least once every `liveness_interval` so the
    // metric `probe_runs_total{probe=...}` keeps a non-zero rate on
    // dashboards and operators get a continuous "this probe target is
    // still reachable through this path" signal. `Duration::ZERO`
    // disables the override (legacy behaviour: skip can hold
    // indefinitely while traffic flows). The first cycle after process
    // start has `last_full_probe_at = None`, which satisfies the
    // override and bootstraps the pulse without a special case.
    if !liveness_interval.is_zero()
        && status
            .last_full_probe_at
            .is_none_or(|t| now.saturating_duration_since(t) >= liveness_interval)
    {
        return false;
    }
    tcp_active && tcp_currently_healthy && tcp_no_cooldown
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_probe_attempt_with_timeout(
    dns_cache: Arc<outline_transport::DnsCache>,
    group: String,
    uplink: Uplink,
    probe: ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: TransportMode,
    effective_udp_mode: TransportMode,
    warm_tcp_slot: Option<WarmTcpProbeSlot>,
    warm_udp_slot: Option<WarmUdpProbeSlot>,
) -> Result<ProbeOutcome> {
    // Outer probe-cycle deadline budget: each enabled application-level
    // sub-probe (ws / http / tcp-tunnel / tls / dns) may cost up to
    // `probe.timeout` on the wire. Without `tls` here, a config that uses
    // only `[probe.tls] + [probe.dns]` lands `tcp_budget = 0`, the cycle
    // gets `timeout_duration = 1 × probe.timeout + 1s` instead of the
    // intended `2 × probe.timeout + 1s`, and a TLS handshake that runs
    // close to the per-attempt deadline can be aborted by the outer
    // wrapper before `record_attempt` finalises — leaving `probe="tls"`
    // metrics flat at zero while DNS still passes.
    let tcp_budget = (probe.ws.enabled
        || probe.http.is_some()
        || probe.tcp.is_some()
        || probe.tls.is_some()) as u32;
    let udp_budget = (uplink.supports_udp() && (probe.ws.enabled || probe.dns.is_some())) as u32;
    let transport_budgets = (tcp_budget + udp_budget).max(1);
    let timeout_duration = probe
        .timeout
        .saturating_mul(transport_budgets)
        .saturating_add(Duration::from_secs(1));
    let mut probe_task = tokio::spawn(async move {
        probe_uplink(
            &dns_cache,
            &group,
            &uplink,
            &probe,
            dial_limit,
            effective_tcp_mode,
            effective_udp_mode,
            warm_tcp_slot,
            warm_udp_slot,
        )
        .await
    });
    let timeout_sleep = sleep(timeout_duration);
    tokio::pin!(timeout_sleep);

    tokio::select! {
        joined = &mut probe_task => match joined {
            Ok(result) => result,
            Err(error) => Err(anyhow!("probe task failed: {error}")),
        },
        _ = &mut timeout_sleep => {
            probe_task.abort();
            let _ = probe_task.await;
            Err(anyhow!("probe timed out after {:?}", timeout_duration))
        }
    }
}

impl UplinkManager {
    pub fn spawn_probe_loop(&self) {
        if !self.inner.probe.enabled() {
            return;
        }

        let manager = self.clone();
        let mut shutdown = self.shutdown_rx();
        tokio::spawn(async move {
            manager.probe_all().await;
            loop {
                // Wake up either when the scheduled interval elapses or when a
                // runtime failure triggers an early wakeup (probe_wakeup).
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = sleep(manager.inner.probe.interval) => {}
                    _ = manager.inner.probe_wakeup.notified() => {}
                }
                manager.probe_all().await;
            }
        });
    }

    pub(crate) async fn probe_all(&self) {
        let mut tasks = tokio::task::JoinSet::new();
        let now = Instant::now();
        for (index, uplink) in self.inner.uplinks.iter().enumerate() {
            // Skip the probe if recent traffic demonstrates the uplink is alive
            // AND it is already marked healthy.  We must NOT skip when the uplink
            // is unhealthy (tcp_healthy == Some(false) or None): in that case the
            // probe is the only mechanism that can confirm recovery and restore
            // the uplink to healthy status.  Skipping when unhealthy would leave
            // the health state stuck — a lingering session on the failed uplink
            // would prevent the probe from ever running and the uplink would
            // never come back online.
            {
                let status = self.inner.read_status(index);
                let s = &status;
                let threshold = self.inner.probe.interval;
                let chunk0_failure_window = self.inner.load_balancing.chunk0_failure_window;
                let liveness_interval = self.inner.probe.liveness_interval;
                // Recent traffic is enough to skip the probe only while there
                // is no active runtime-failure cooldown. Once a cooldown is
                // set, we must run the probe even in global scope so it can
                // confirm whether the active uplink is actually broken and let
                // strict selection move new sessions away from it. Operators
                // can disable the skip entirely via `skip_when_active = false`
                // — useful when they want continuous probe coverage on
                // dashboards even for the active uplink (the trade-off is
                // ~1 extra application-level handshake per cycle per active
                // uplink). The liveness override (`liveness_interval`) is
                // weaker — it lets skip hold up to that duration, then
                // forces a single cycle to pulse metrics, then can skip
                // again until the next interval. Default 5 min.
                if self.inner.probe.skip_when_active
                    && should_skip_probe_cycle_for_recent_activity(
                        s,
                        now,
                        threshold,
                        chunk0_failure_window,
                        liveness_interval,
                    )
                {
                    let udp_active =
                        s.udp.last_active.is_some_and(|t| now.duration_since(t) < threshold);
                    debug!(
                        uplink = %uplink.name,
                        last_active_tcp_ms = s.tcp.last_active.map(|t| now.duration_since(t).as_millis()),
                        last_active_udp_ms = s.udp.last_active.map(|t| now.duration_since(t).as_millis()),
                        udp_also_active = udp_active,
                        "skipping probe cycle: real traffic observed and uplink is healthy"
                    );
                    continue;
                }
            }
            // Past the skip gate — this cycle will run. Stamp
            // `last_full_probe_at` *now* so the liveness override in
            // `should_skip_probe_cycle_for_recent_activity` can read the
            // freshness on the next cycle without depending on the probe
            // result. Stamping early (vs. after the probe finishes via
            // `process_probe_ok` / `process_probe_err`) ensures a probe
            // that errors out hard still resets the liveness window —
            // otherwise a series of timeout-aborted cycles would
            // pin-pong the override every cycle instead of every
            // `liveness_interval`.
            self.inner.with_status_mut(index, |s| {
                s.last_full_probe_at = Some(now);
            });

            let uplink = uplink.clone();
            let probe = self.inner.probe.clone();
            let execution_limit = Arc::clone(&self.inner.probe_execution_limit);
            let dial_limit = Arc::clone(&self.inner.probe_dial_limit);
            let probe_attempts = probe.attempts.max(1);
            let group_name = self.inner.group_name.clone();
            let dns_cache = Arc::clone(&self.inner.dns_cache);
            // Use the effective TCP/UDP WS modes so that when H3 is in the
            // downgrade window the probe tests H2 connectivity instead.
            // This prevents the probe from clearing h3_*_downgrade_until
            // prematurely via a successful H3 ping/pong that does not
            // represent real data-path behaviour (the server may reject
            // actual streams with APPLICATION_CLOSE while still answering
            // ping/pong at the connection level).
            let effective_tcp_mode = self.effective_tcp_mode(index).await;
            let effective_udp_mode = self.effective_udp_mode(index).await;
            // VLESS and Shadowsocks-over-WS uplinks reuse warm probe pipes.
            // Plain Shadowsocks (direct sockets, no WS handshake) still
            // dials fresh — there is no handshake to amortize and passing
            // `None` keeps the probe code path identical.
            let (warm_tcp_slot, warm_udp_slot): (
                Option<WarmTcpProbeSlot>,
                Option<WarmUdpProbeSlot>,
            ) = if matches!(
                uplink.transport,
                crate::config::UplinkTransport::Vless | crate::config::UplinkTransport::Ws,
            ) {
                (
                    Some(Arc::clone(self.inner.warm_tcp_probe_slot(index))),
                    Some(Arc::clone(self.inner.warm_udp_probe_slot(index))),
                )
            } else {
                (None, None)
            };
            tasks.spawn(async move {
                let _permit = execution_limit
                    .acquire_owned()
                    .await
                    .expect("probe execution semaphore closed");
                // Retry the probe up to `attempts` times within one cycle.
                // As soon as any attempt returns Ok we accept that result and
                // stop; only if every attempt fails do we propagate the error.
                // This makes each probe cycle resilient to transient network
                // blips that would otherwise needlessly increment the
                // consecutive-failure counter.
                let mut outcome = Err(anyhow!("no probe attempts"));
                for attempt in 0..probe_attempts {
                    outcome = run_probe_attempt_with_timeout(
                        Arc::clone(&dns_cache),
                        group_name.clone(),
                        uplink.clone(),
                        probe.clone(),
                        Arc::clone(&dial_limit),
                        effective_tcp_mode,
                        effective_udp_mode,
                        warm_tcp_slot.clone(),
                        warm_udp_slot.clone(),
                    )
                    .await;
                    if outcome.is_ok() {
                        break;
                    }
                    if attempt + 1 < probe_attempts {
                        sleep(Duration::from_millis(500)).await;
                    }
                }
                (index, uplink, outcome, effective_tcp_mode, effective_udp_mode)
            });
        }

        let mut h3_tcp_recovery_needed: Vec<(usize, Uplink)> = Vec::new();
        let mut h3_udp_recovery_needed: Vec<(usize, Uplink)> = Vec::new();

        while let Some(joined) = tasks.join_next().await {
            let (index, uplink, outcome, effective_tcp_mode, effective_udp_mode) = match joined {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, "probe task failed");
                    continue;
                },
            };
            let mut refill_tcp = false;
            let mut refill_udp = false;
            // Whether to chase up with a fallback-wire probe pass. Decided
            // against the primary outcome before the match consumes it.
            let primary_failing = match &outcome {
                Ok(r) => !r.tcp_ok || (r.udp_applicable && !r.udp_ok),
                Err(_) => true,
            };
            match outcome {
                Ok(result) => {
                    (refill_tcp, refill_udp) = self.process_probe_ok(
                        index,
                        &uplink,
                        result,
                        effective_tcp_mode,
                        effective_udp_mode,
                        &mut h3_tcp_recovery_needed,
                        &mut h3_udp_recovery_needed,
                    );
                },
                Err(error) => {
                    self.process_probe_err(
                        index,
                        &uplink,
                        error,
                        effective_tcp_mode,
                        effective_udp_mode,
                    );
                },
            }
            // Per-wire probe walk: when primary failed, validate the
            // active fallback wire so `last_any_wire_success` (and the
            // dashboard / Prometheus `*_health_effective` view) reflect
            // a working fallback even on a passive uplink with no
            // client traffic. No-op when the uplink has no fallbacks.
            if primary_failing && !uplink.fallbacks.is_empty() {
                self.run_fallback_wire_probe(
                    index,
                    &uplink,
                    Arc::clone(&self.inner.dns_cache),
                    self.inner.probe.clone(),
                    Arc::clone(&self.inner.probe_dial_limit),
                )
                .await;
            }

            if refill_tcp {
                self.spawn_refill(index, TransportKind::Tcp);
            } else {
                self.clear_standby(index, TransportKind::Tcp).await;
            }
            if refill_udp {
                self.spawn_refill(index, TransportKind::Udp);
            } else if uplink.supports_udp() {
                // Only clear UDP standby when UDP is actually configured.
                // Without this guard a TCP-only uplink would keep clearing an
                // already-empty UDP pool on every probe cycle.
                self.clear_standby(index, TransportKind::Udp).await;
            }
        }

        // Carrier-recovery re-probes: for each uplink where the regular
        // probe succeeded against the **capped** carrier during an
        // active downgrade window, run an explicit probe at the
        // **configured** carrier. A success clears the cap immediately
        // (instead of waiting out `mode_downgrade_duration`) so traffic
        // returns to configured the moment the server is confirmed
        // ready; a failure extends the window with `RecoveryReprobeFail`
        // to suppress oscillation while configured is still unstable.
        // Symmetric across WS+H3 and VLESS+XHTTP (H3/H2) configured uplinks.
        self.run_h3_recovery_probes(h3_tcp_recovery_needed, TransportKind::Tcp).await;
        self.run_h3_recovery_probes(h3_udp_recovery_needed, TransportKind::Udp).await;
    }
}

#[cfg(test)]
#[path = "tests/scheduler.rs"]
mod tests;
