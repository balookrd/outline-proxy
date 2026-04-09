use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, warn};

use crate::types::UplinkTransport;

use super::probe_impl::probe_uplink;
use super::scoring::{add_penalty, cooldown_active, update_rtt_ewma};
use super::types::TransportKind;

use super::UplinkManager;

impl UplinkManager {
    pub(super) async fn probe_all(&self) {
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
                let statuses = self.inner.statuses.read().await;
                let s = &statuses[index];
                let threshold = self.inner.probe.interval;
                let tcp_active = s
                    .last_active_tcp
                    .map_or(false, |t| now.duration_since(t) < threshold);
                let tcp_currently_healthy = s.tcp_healthy == Some(true);
                // Do NOT skip if there is an active cooldown: a runtime
                // connection failure was reported, meaning the uplink may be
                // down even though tcp_healthy is still Some(true) (the probe
                // is the authoritative health source when enabled, so
                // report_runtime_failure does not flip tcp_healthy directly).
                // We must run the probe so it can detect the failure and
                // trigger failover.
                let tcp_no_cooldown = !cooldown_active(s, TransportKind::Tcp, now);
                // Skip the probe cycle only when there is no active runtime-failure
                // cooldown.  An active cooldown means a recent connection to this
                // uplink timed out or errored; we must run the probe so it can
                // confirm whether the failure is persistent and, if so, set
                // tcp_healthy = Some(false) to trigger failover.
                // NOTE: report_active_traffic fires as soon as the first chunk is
                // forwarded *to* the upstream — before we know whether the upstream
                // will reply.  A failing connection therefore still records activity,
                // so tcp_active alone is not a reliable liveness signal when a
                // cooldown is present.
                let skip_allowed = tcp_no_cooldown;
                if tcp_active && tcp_currently_healthy && skip_allowed {
                    let udp_active = s
                        .last_active_udp
                        .map_or(false, |t| now.duration_since(t) < threshold);
                    debug!(
                        uplink = %uplink.name,
                        last_active_tcp_ms = s.last_active_tcp.map(|t| now.duration_since(t).as_millis()),
                        last_active_udp_ms = s.last_active_udp.map(|t| now.duration_since(t).as_millis()),
                        udp_also_active = udp_active,
                        had_cooldown = !tcp_no_cooldown,
                        "skipping probe cycle: real traffic observed and uplink is healthy"
                    );
                    continue;
                }
            }

            let uplink = Arc::clone(uplink);
            let probe = self.inner.probe.clone();
            let timeout_duration = self.inner.probe.timeout;
            let execution_limit = Arc::clone(&self.inner.probe_execution_limit);
            let dial_limit = Arc::clone(&self.inner.probe_dial_limit);
            let probe_attempts = probe.attempts.max(1);
            // Use the effective TCP WS mode so that when H3 is in the
            // downgrade window the probe tests H2 connectivity instead.
            // This prevents the probe from clearing h3_tcp_downgrade_until
            // prematurely via a successful H3 ping/pong that does not
            // represent real data-path behaviour (the server may reject
            // actual streams with APPLICATION_CLOSE while still answering
            // ping/pong at the connection level).
            let effective_tcp_mode = self.effective_tcp_ws_mode(index).await;
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
                    outcome = timeout(
                        timeout_duration,
                        probe_uplink(&uplink, &probe, Arc::clone(&dial_limit), effective_tcp_mode),
                    )
                    .await
                    .unwrap_or_else(|_| {
                        Err(anyhow!("probe timed out after {:?}", timeout_duration))
                    });
                    if outcome.is_ok() {
                        break;
                    }
                    if attempt + 1 < probe_attempts {
                        sleep(Duration::from_millis(500)).await;
                    }
                }
                (index, uplink, outcome)
            });
        }

        while let Some(joined) = tasks.join_next().await {
            let (index, uplink, outcome) = match joined {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, "probe task failed");
                    continue;
                }
            };
            let mut refill_tcp = false;
            let mut refill_udp = false;
            match outcome {
                Ok(result) => {
                    let (tcp_rtt_ewma_ms, udp_rtt_ewma_ms) = {
                        let now = Instant::now();
                        let min_failures = self.inner.probe.min_failures;
                        let mut statuses = self.inner.statuses.write().await;
                        let status = &mut statuses[index];
                        status.last_checked = Some(now);
                        status.tcp_latency = result.tcp_latency;
                        status.udp_latency = result.udp_latency;
                        update_rtt_ewma(
                            &mut status.tcp_rtt_ewma,
                            result.tcp_latency,
                            self.inner.load_balancing.rtt_ewma_alpha,
                        );
                        update_rtt_ewma(
                            &mut status.udp_rtt_ewma,
                            result.udp_latency,
                            self.inner.load_balancing.rtt_ewma_alpha,
                        );
                        if !result.tcp_ok {
                            status.tcp_consecutive_successes = 0;
                            status.tcp_consecutive_failures =
                                status.tcp_consecutive_failures.saturating_add(1);
                            if status.tcp_consecutive_failures >= min_failures as u32 {
                                status.tcp_healthy = Some(false);
                                add_penalty(
                                    &mut status.tcp_penalty,
                                    now,
                                    &self.inner.load_balancing,
                                );
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
                            if uplink.transport == UplinkTransport::Websocket
                                && uplink.tcp_ws_mode == crate::types::WsTransportMode::H3
                            {
                                let downgrade_until =
                                    now + self.inner.load_balancing.h3_downgrade_duration;
                                if status.h3_tcp_downgrade_until.map_or(true, |t| t < now) {
                                    warn!(
                                        uplink = %uplink.name,
                                        downgrade_secs = self.inner.load_balancing.h3_downgrade_duration.as_secs(),
                                        "H3 TCP probe failed, downgrading to H2 for next probe cycle"
                                    );
                                }
                                status.h3_tcp_downgrade_until = Some(downgrade_until);
                            }
                        } else {
                            status.tcp_consecutive_failures = 0;
                            status.tcp_consecutive_successes =
                                status.tcp_consecutive_successes.saturating_add(1);
                            status.tcp_healthy = Some(true);
                            // Do NOT clear the runtime-failure cooldown here.  The probe only
                            // tests SS-server reachability (TCP/WS handshake), not the full
                            // data path to the actual target.  A healthy probe therefore does
                            // not mean user connections will succeed.  The cooldown is the only
                            // signal that the data path is broken; it must expire naturally
                            // (failure_cooldown_secs) so that candidate selection has a chance
                            // to switch away.  Clearing it here would let the probe immediately
                            // re-admit a broken uplink on every cycle.
                            // Do NOT clear h3_tcp_downgrade_until here.  The probe uses the
                            // effective (possibly downgraded) WS mode, so a successful probe
                            // only confirms H2 connectivity during a downgrade window — it does
                            // not prove that H3 is healthy again.  H3 recovery is tested
                            // naturally: once the downgrade timer expires, the next real
                            // connection attempt uses H3 and resets the timer only if it fails.
                        }
                        if result.udp_applicable {
                            if !result.udp_ok {
                                status.udp_consecutive_failures =
                                    status.udp_consecutive_failures.saturating_add(1);
                                if status.udp_consecutive_failures >= min_failures as u32 {
                                    status.udp_healthy = Some(false);
                                    add_penalty(
                                        &mut status.udp_penalty,
                                        now,
                                        &self.inner.load_balancing,
                                    );
                                }
                            } else {
                                status.udp_consecutive_failures = 0;
                                status.udp_consecutive_successes =
                                    status.udp_consecutive_successes.saturating_add(1);
                                status.udp_healthy = Some(true);
                                // Do NOT clear the runtime-failure cooldown here.  The probe only
                                // tests SS-server reachability, not the full data path to the
                                // actual target.  The cooldown must expire naturally so that
                                // candidate selection can switch away from a broken uplink.
                            }
                        }
                        if result.tcp_ok && (!result.udp_applicable || result.udp_ok) {
                            status.last_error = None;
                        }
                        (
                            status
                                .tcp_rtt_ewma
                                .map(|v| v.as_millis() as u64)
                                .unwrap_or_default(),
                            status
                                .udp_rtt_ewma
                                .map(|v| v.as_millis() as u64)
                                .unwrap_or_default(),
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
                    refill_tcp = result.tcp_ok;
                    // When UDP is not configured for this uplink, leave the
                    // standby pool alone (don't clear it, don't refill it).
                    refill_udp = result.udp_applicable && result.udp_ok;
                }
                Err(error) => {
                    {
                        let now = Instant::now();
                        let min_failures = self.inner.probe.min_failures;
                        let mut statuses = self.inner.statuses.write().await;
                        let status = &mut statuses[index];
                        status.last_checked = Some(now);
                        status.tcp_consecutive_successes = 0;
                        status.tcp_consecutive_failures =
                            status.tcp_consecutive_failures.saturating_add(1);
                        if status.tcp_consecutive_failures >= min_failures as u32 {
                            status.tcp_healthy = Some(false);
                            add_penalty(&mut status.tcp_penalty, now, &self.inner.load_balancing);
                        }
                        // Only penalise UDP when it is actually configured.
                        // The probe Err path is usually a TCP connect failure;
                        // penalising UDP here when there is no udp_ws_url would
                        // permanently mark UDP unhealthy for TCP-only uplinks.
                        if uplink.supports_udp() {
                            status.udp_consecutive_failures =
                                status.udp_consecutive_failures.saturating_add(1);
                            if status.udp_consecutive_failures >= min_failures as u32 {
                                status.udp_healthy = Some(false);
                                add_penalty(
                                    &mut status.udp_penalty,
                                    now,
                                    &self.inner.load_balancing,
                                );
                            }
                        }
                        // Probe connection itself failed (ws connect / timeout).
                        // Same H3 downgrade logic as the tcp_ok=false case above.
                        if uplink.transport == UplinkTransport::Websocket
                            && uplink.tcp_ws_mode == crate::types::WsTransportMode::H3
                        {
                            let downgrade_until =
                                now + self.inner.load_balancing.h3_downgrade_duration;
                            if status.h3_tcp_downgrade_until.map_or(true, |t| t < now) {
                                warn!(
                                    uplink = %uplink.name,
                                    error = %format!("{error:#}"),
                                    downgrade_secs = self.inner.load_balancing.h3_downgrade_duration.as_secs(),
                                    "H3 probe connection failed, downgrading TCP to H2"
                                );
                            }
                            status.h3_tcp_downgrade_until = Some(downgrade_until);
                        }
                        status.last_error = Some(format!("{error:#}"));
                    }
                    warn!(uplink = %uplink.name, error = %format!("{error:#}"), "uplink probe failed");
                }
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
    }
}
