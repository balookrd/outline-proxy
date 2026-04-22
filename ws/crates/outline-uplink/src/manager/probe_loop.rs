use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep};
use tracing::{debug, info, warn};

use crate::config::ProbeConfig;
use crate::config::{UplinkTransport, WsTransportMode};

use super::super::probe::probe_uplink;
use super::super::selection::cooldown_active;
use super::super::types::{ProbeOutcome, TransportKind, UplinkManager, UplinkStatus};
use super::super::utils::{add_penalty, update_rtt_ewma};

fn should_skip_probe_cycle_for_recent_activity(
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
async fn run_probe_attempt_with_timeout(
    dns_cache: Arc<outline_transport::DnsCache>,
    group: String,
    uplink: Arc<crate::config::UplinkConfig>,
    probe: ProbeConfig,
    dial_limit: Arc<Semaphore>,
    effective_tcp_mode: crate::config::WsTransportMode,
    effective_udp_mode: crate::config::WsTransportMode,
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

            let uplink = Arc::clone(uplink);
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
                        Arc::clone(&uplink),
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

        let mut h3_tcp_recovery_needed: Vec<(usize, Arc<crate::config::UplinkConfig>)> =
            Vec::new();
        let mut h3_udp_recovery_needed: Vec<(usize, Arc<crate::config::UplinkConfig>)> =
            Vec::new();

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
        // the full h3_downgrade_duration to expire) so traffic switches back to
        // H3 as soon as the server is confirmed ready.  A failing result extends
        // the downgrade window by another h3_downgrade_duration from now,
        // preventing oscillation if H3 is still unstable.
        self.run_h3_recovery_probes(h3_tcp_recovery_needed, TransportKind::Tcp).await;
        self.run_h3_recovery_probes(h3_udp_recovery_needed, TransportKind::Udp).await;
    }

    #[allow(clippy::too_many_arguments)]
    fn process_probe_ok(
        &self,
        index: usize,
        uplink: &Arc<crate::config::UplinkConfig>,
        result: ProbeOutcome,
        effective_tcp_mode: WsTransportMode,
        effective_udp_mode: WsTransportMode,
        h3_tcp_recovery: &mut Vec<(usize, Arc<crate::config::UplinkConfig>)>,
        h3_udp_recovery: &mut Vec<(usize, Arc<crate::config::UplinkConfig>)>,
    ) -> (bool, bool) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures;
        let rtt_ewma_alpha = self.inner.load_balancing.rtt_ewma_alpha;
        let h3_downgrade_duration = self.inner.load_balancing.h3_downgrade_duration;
        let load_balancing = self.inner.load_balancing.clone();
        // Read current h3_downgrade_until values before mutating so
        // we can emit warn! without holding the write lock.
        let (prev_tcp_h3, prev_udp_h3) = {
            let s = self.inner.read_status(index);
            (s.tcp.h3_downgrade_until, s.udp.h3_downgrade_until)
        };
        // Emit warn! for H3 downgrades before acquiring the write lock.
        if !result.tcp_ok
            && uplink.transport == UplinkTransport::Ws
            && uplink.tcp_ws_mode == crate::config::WsTransportMode::H3
            && prev_tcp_h3.is_none_or(|t| t < now)
        {
            warn!(
                uplink = %uplink.name,
                downgrade_secs = h3_downgrade_duration.as_secs(),
                "H3 TCP probe failed, downgrading to H2 for next probe cycle"
            );
        }
        if result.udp_applicable
            && !result.udp_ok
            && uplink.transport == UplinkTransport::Ws
            && uplink.udp_ws_mode == WsTransportMode::H3
            && prev_udp_h3.is_none_or(|t| t < now)
        {
            warn!(
                uplink = %uplink.name,
                downgrade_secs = h3_downgrade_duration.as_secs(),
                "H3 UDP probe failed, downgrading to H2 for next probe cycle"
            );
        }
        let mut needs_h3_tcp_recovery = false;
        let mut needs_h3_udp_recovery = false;
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(now);
            status.tcp.latency = result.tcp_latency;
            status.udp.latency = result.udp_latency;
            update_rtt_ewma(&mut status.tcp.rtt_ewma, result.tcp_latency, rtt_ewma_alpha);
            update_rtt_ewma(&mut status.udp.rtt_ewma, result.udp_latency, rtt_ewma_alpha);
            if !result.tcp_ok {
                status.tcp.consecutive_successes = 0;
                status.tcp.consecutive_failures =
                    status.tcp.consecutive_failures.saturating_add(1);
                if status.tcp.consecutive_failures >= min_failures as u32 {
                    status.tcp.healthy = Some(false);
                    add_penalty(&mut status.tcp.penalty, now, &load_balancing);
                }
                // If this uplink is configured for H3 and the TCP
                // probe failed, downgrade to H2 for the next probe
                // cycle.  Without this, intermittent H3 probe
                // failures cause probe-driven flapping in
                // active-passive / global scope: the probe
                // alternates pass (H3) / fail (H3) → switch to
                // backup / switch back to primary on every cycle.
                // With H2 downgrade, recovery probing uses H2
                // which is stable, and H3 is only retried after the
                // downgrade timer expires.
                if uplink.transport == UplinkTransport::Ws
                    && uplink.tcp_ws_mode == crate::config::WsTransportMode::H3
                {
                    status.tcp.h3_downgrade_until = Some(now + h3_downgrade_duration);
                }
            } else {
                status.tcp.consecutive_failures = 0;
                status.tcp.consecutive_successes =
                    status.tcp.consecutive_successes.saturating_add(1);
                status.tcp.healthy = Some(true);
                // Only clear runtime-failure cooldown when the probe confirms TCP is
                // healthy. Clearing unconditionally would make a recently-failed
                // uplink immediately eligible again, causing oscillation under load.
                status.tcp.cooldown_until = None;
                // Do NOT clear h3_tcp_downgrade_until here.  The probe uses the
                // effective (possibly downgraded) WS mode, so a successful probe
                // only confirms H2 connectivity during a downgrade window — it does
                // not prove that H3 is healthy again.  Instead, schedule an H3
                // recovery re-probe below to confirm H3 liveness explicitly.
                if effective_tcp_mode == WsTransportMode::H2
                    && uplink.transport == UplinkTransport::Ws
                    && uplink.tcp_ws_mode == WsTransportMode::H3
                    && status.tcp.h3_downgrade_until.is_some_and(|t| t > now)
                {
                    needs_h3_tcp_recovery = true;
                }
            }
            if result.udp_applicable {
                if !result.udp_ok {
                    status.udp.consecutive_failures =
                        status.udp.consecutive_failures.saturating_add(1);
                    if status.udp.consecutive_failures >= min_failures as u32 {
                        status.udp.healthy = Some(false);
                        add_penalty(&mut status.udp.penalty, now, &load_balancing);
                    }
                    // Mirror of the TCP H3 downgrade above for UDP.
                    if uplink.transport == UplinkTransport::Ws
                        && uplink.udp_ws_mode == WsTransportMode::H3
                    {
                        status.udp.h3_downgrade_until = Some(now + h3_downgrade_duration);
                    }
                } else {
                    status.udp.consecutive_failures = 0;
                    status.udp.consecutive_successes =
                        status.udp.consecutive_successes.saturating_add(1);
                    status.udp.healthy = Some(true);
                    status.udp.cooldown_until = None;
                    // Schedule UDP H3 recovery re-probe — mirror of the
                    // TCP path.  Successful H2 probe doesn't prove H3 is
                    // back, so verify it explicitly below.
                    if effective_udp_mode == WsTransportMode::H2
                        && uplink.transport == UplinkTransport::Ws
                        && uplink.udp_ws_mode == WsTransportMode::H3
                        && status.udp.h3_downgrade_until.is_some_and(|t| t > now)
                    {
                        needs_h3_udp_recovery = true;
                    }
                }
            }
            if result.tcp_ok && (!result.udp_applicable || result.udp_ok) {
                status.last_error = None;
            }
        });
        if needs_h3_tcp_recovery {
            h3_tcp_recovery.push((index, Arc::clone(uplink)));
        }
        if needs_h3_udp_recovery {
            h3_udp_recovery.push((index, Arc::clone(uplink)));
        }
        let (tcp_rtt_ewma_ms, udp_rtt_ewma_ms) = {
            let s = self.inner.read_status(index);
            (
                s.tcp.rtt_ewma.map(|v| v.as_millis() as u64).unwrap_or_default(),
                s.udp.rtt_ewma.map(|v| v.as_millis() as u64).unwrap_or_default(),
            )
        };
        debug!(
            uplink = %uplink.name,
            tcp_healthy = result.tcp_ok,
            udp_healthy = result.udp_ok,
            tcp_latency_ms = result.tcp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
            udp_latency_ms = result.udp_latency.map(|v| v.as_millis() as u64).unwrap_or_default(),
            tcp_rtt_ewma_ms,
            udp_rtt_ewma_ms,
            "uplink probe succeeded"
        );
        let refill_tcp = result.tcp_ok;
        // When UDP is not configured for this uplink, leave the
        // standby pool alone (don't clear it, don't refill it).
        let refill_udp = result.udp_applicable && result.udp_ok;
        (refill_tcp, refill_udp)
    }

    fn process_probe_err(
        &self,
        index: usize,
        uplink: &Arc<crate::config::UplinkConfig>,
        error: anyhow::Error,
    ) {
        let now = Instant::now();
        let min_failures = self.inner.probe.min_failures;
        let h3_downgrade_duration = self.inner.load_balancing.h3_downgrade_duration;
        let load_balancing = self.inner.load_balancing.clone();
        // Read h3_downgrade_until before mutating for warn! emission.
        let (prev_tcp_h3, prev_udp_h3) = {
            let s = self.inner.read_status(index);
            (s.tcp.h3_downgrade_until, s.udp.h3_downgrade_until)
        };
        // Emit warn! before acquiring write lock.
        if uplink.transport == UplinkTransport::Ws
            && uplink.tcp_ws_mode == crate::config::WsTransportMode::H3
            && prev_tcp_h3.is_none_or(|t| t < now)
        {
            warn!(
                uplink = %uplink.name,
                error = %format!("{error:#}"),
                downgrade_secs = h3_downgrade_duration.as_secs(),
                "H3 probe connection failed, downgrading TCP to H2"
            );
        }
        if uplink.supports_udp()
            && uplink.transport == UplinkTransport::Ws
            && uplink.udp_ws_mode == crate::config::WsTransportMode::H3
            && prev_udp_h3.is_none_or(|t| t < now)
        {
            warn!(
                uplink = %uplink.name,
                error = %format!("{error:#}"),
                downgrade_secs = h3_downgrade_duration.as_secs(),
                "H3 probe connection failed, downgrading UDP to H2"
            );
        }
        let error_text = format!("{error:#}");
        self.inner.with_status_mut(index, |status| {
            status.last_checked = Some(now);
            status.tcp.consecutive_successes = 0;
            status.tcp.consecutive_failures =
                status.tcp.consecutive_failures.saturating_add(1);
            if status.tcp.consecutive_failures >= min_failures as u32 {
                status.tcp.healthy = Some(false);
                add_penalty(&mut status.tcp.penalty, now, &load_balancing);
            }
            // Only penalise UDP when it is actually configured.
            // The probe Err path is usually a TCP connect failure;
            // penalising UDP here when there is no udp_ws_url would
            // permanently mark UDP unhealthy for TCP-only uplinks.
            if uplink.supports_udp() {
                status.udp.consecutive_failures =
                    status.udp.consecutive_failures.saturating_add(1);
                if status.udp.consecutive_failures >= min_failures as u32 {
                    status.udp.healthy = Some(false);
                    add_penalty(&mut status.udp.penalty, now, &load_balancing);
                }
            }
            // Probe connection itself failed (ws connect / timeout).
            // Same H3 downgrade logic as the tcp_ok=false case above.
            if uplink.transport == UplinkTransport::Ws
                && uplink.tcp_ws_mode == crate::config::WsTransportMode::H3
            {
                status.tcp.h3_downgrade_until = Some(now + h3_downgrade_duration);
            }
            // Same for UDP — when the uplink supports UDP and is on H3,
            // a probe-level failure also forces UDP H2 fallback so the
            // failover loop on a broken H3 server doesn't spin.
            if uplink.supports_udp()
                && uplink.transport == UplinkTransport::Ws
                && uplink.udp_ws_mode == crate::config::WsTransportMode::H3
            {
                status.udp.h3_downgrade_until = Some(now + h3_downgrade_duration);
            }
            status.last_error = Some(error_text.clone());
        });
        warn!(uplink = %uplink.name, error = %format!("{error:#}"), "uplink probe failed");
    }

    async fn run_h3_recovery_probes(
        &self,
        needed: Vec<(usize, Arc<crate::config::UplinkConfig>)>,
        which: TransportKind,
    ) {
        if needed.is_empty() {
            return;
        }
        let mut recovery_tasks = tokio::task::JoinSet::new();
        for (index, uplink) in needed {
            let probe = self.inner.probe.clone();
            let dial_limit = Arc::clone(&self.inner.probe_dial_limit);
            let execution_limit = Arc::clone(&self.inner.probe_execution_limit);
            let group_name = self.inner.group_name.clone();
            let dns_cache = Arc::clone(&self.inner.dns_cache);
            recovery_tasks.spawn(async move {
                let _permit = execution_limit
                    .acquire_owned()
                    .await
                    .expect("probe execution semaphore closed");
                // Run probe with H3 for the transport we're recovering, and
                // keep the other transport at its native mode (it doesn't
                // affect the recovery decision but avoids penalising it).
                let (eff_tcp, eff_udp) = match which {
                    TransportKind::Tcp => (WsTransportMode::H3, uplink.udp_ws_mode),
                    TransportKind::Udp => (uplink.tcp_ws_mode, WsTransportMode::H3),
                };
                let outcome = run_probe_attempt_with_timeout(
                    Arc::clone(&dns_cache),
                    group_name,
                    Arc::clone(&uplink),
                    probe,
                    dial_limit,
                    eff_tcp,
                    eff_udp,
                )
                .await;
                (index, uplink, outcome)
            });
        }
        while let Some(joined) = recovery_tasks.join_next().await {
            let (index, uplink, outcome) = match joined {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, kind = ?which, "H3 recovery probe task failed");
                    continue;
                },
            };
            let now = Instant::now();
            let h3_downgrade_duration = self.inner.load_balancing.h3_downgrade_duration;
            let recovered = match which {
                TransportKind::Tcp => matches!(&outcome, Ok(r) if r.tcp_ok),
                TransportKind::Udp => matches!(&outcome, Ok(r) if r.udp_applicable && r.udp_ok),
            };
            if recovered {
                info!(
                    uplink = %uplink.name,
                    kind = ?which,
                    "H3 recovery confirmed by re-probe, clearing downgrade window early"
                );
                self.inner.with_status_mut(index, |status| match which {
                    TransportKind::Tcp => status.tcp.h3_downgrade_until = None,
                    TransportKind::Udp => status.udp.h3_downgrade_until = None,
                });
            } else {
                let new_until = now + h3_downgrade_duration;
                let current = {
                    let s = self.inner.read_status(index);
                    match which {
                        TransportKind::Tcp => s.tcp.h3_downgrade_until,
                        TransportKind::Udp => s.udp.h3_downgrade_until,
                    }
                };
                if current.is_none_or(|t| t < new_until) {
                    debug!(
                        uplink = %uplink.name,
                        kind = ?which,
                        downgrade_secs = h3_downgrade_duration.as_secs(),
                        "H3 still unreachable after recovery probe, extending downgrade window"
                    );
                    self.inner.with_status_mut(index, |status| match which {
                        TransportKind::Tcp => status.tcp.h3_downgrade_until = Some(new_until),
                        TransportKind::Udp => status.udp.h3_downgrade_until = Some(new_until),
                    });
                }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::Instant;

    use crate::types::UplinkStatus;

    use super::should_skip_probe_cycle_for_recent_activity;

    #[test]
    fn recent_healthy_traffic_skips_probe_without_cooldown() {
        let now = Instant::now();
        let status = UplinkStatus {
            tcp: crate::types::PerTransportStatus {
                healthy: Some(true),
                last_active: Some(now - Duration::from_secs(1)),
                ..Default::default()
            },
            ..UplinkStatus::default()
        };

        assert!(should_skip_probe_cycle_for_recent_activity(
            &status,
            now,
            Duration::from_secs(30),
        ));
    }

    #[test]
    fn active_cooldown_prevents_probe_skip_even_with_recent_traffic() {
        let now = Instant::now();
        let status = UplinkStatus {
            tcp: crate::types::PerTransportStatus {
                healthy: Some(true),
                last_active: Some(now - Duration::from_secs(1)),
                cooldown_until: Some(now + Duration::from_secs(10)),
                ..Default::default()
            },
            ..UplinkStatus::default()
        };

        assert!(!should_skip_probe_cycle_for_recent_activity(
            &status,
            now,
            Duration::from_secs(30),
        ));
    }
}
