use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep};
use tracing::{debug, warn};

use crate::config::{ProbeConfig, WsTransportMode};

use super::super::super::probe::probe_uplink;
use super::super::super::selection::cooldown_active;
use super::super::super::types::{ProbeOutcome, TransportKind, Uplink, UplinkManager, UplinkStatus};

pub(super) fn should_skip_probe_cycle_for_recent_activity(
    status: &UplinkStatus,
    now: Instant,
    interval: Duration,
) -> bool {
    let tcp_active = status
        .tcp
        .last_active
        .is_some_and(|t| now.duration_since(t) < interval);
    let tcp_currently_healthy = status.tcp.healthy == Some(true);
    let tcp_no_cooldown = !cooldown_active(status, TransportKind::Tcp, now);
    tcp_active && tcp_currently_healthy && tcp_no_cooldown
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_probe_attempt_with_timeout(
    dns_cache: Arc<outline_transport::DnsCache>,
    group: String,
    uplink: Uplink,
    probe: ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: WsTransportMode,
    effective_udp_mode: WsTransportMode,
) -> Result<ProbeOutcome> {
    let tcp_budget = (probe.ws.enabled || probe.http.is_some() || probe.tcp.is_some()) as u32;
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
                // Recent traffic is enough to skip the probe only while there
                // is no active runtime-failure cooldown. Once a cooldown is
                // set, we must run the probe even in global scope so it can
                // confirm whether the active uplink is actually broken and let
                // strict selection move new sessions away from it.
                if should_skip_probe_cycle_for_recent_activity(s, now, threshold) {
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
            let effective_tcp_mode = self.effective_tcp_ws_mode(index).await;
            let effective_udp_mode = self.effective_udp_ws_mode(index).await;
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
                    self.process_probe_err(index, &uplink, error);
                },
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

        // H3 recovery re-probes: for each uplink where the H2 probe succeeded
        // during a downgrade window, run an explicit H3 probe.  A successful H3
        // result clears h3_*_downgrade_until immediately (instead of waiting for
        // the full mode_downgrade_duration to expire) so traffic switches back to
        // H3 as soon as the server is confirmed ready.  A failing result extends
        // the downgrade window by another mode_downgrade_duration from now,
        // preventing oscillation if H3 is still unstable.
        self.run_h3_recovery_probes(h3_tcp_recovery_needed, TransportKind::Tcp).await;
        self.run_h3_recovery_probes(h3_udp_recovery_needed, TransportKind::Udp).await;
    }
}

#[cfg(test)]
#[path = "tests/scheduler.rs"]
mod tests;
