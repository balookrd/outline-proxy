use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, warn};

use outline_metrics as metrics;

use super::super::error_classify::{
    classify_runtime_failure_cause, classify_runtime_failure_signature,
};
use super::super::penalty::{add_penalty, current_penalty, update_rtt_ewma};
use super::super::types::{TransportKind, UplinkManager};
use super::mode_downgrade::ModeDowngradeTrigger;

const PROBE_WAKEUP_MIN_INTERVAL: Duration = Duration::from_secs(15);

/// Records `now` as the most recent probe wakeup if at least `min_interval`
/// has elapsed since the previous one.  Returns `true` when the timestamp was
/// refreshed (caller should fire the wakeup), `false` when the rate-limit
/// window suppresses it.
fn mark_probe_wakeup(
    last_wakeup: &mut Option<Instant>,
    now: Instant,
    min_interval: Duration,
) -> bool {
    if last_wakeup.is_some_and(|prev| now.duration_since(prev) < min_interval) {
        return false;
    }
    *last_wakeup = Some(now);
    true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn emit_runtime_failure_metrics(
    kind: &'static str,
    group_name: &str,
    uplink_name: &str,
    failure_cause: &'static str,
    failure_signature: &'static str,
    failure_other_detail: Option<&str>,
    already_in_cooldown: bool,
) {
    if !already_in_cooldown {
        metrics::record_runtime_failure(kind, group_name, uplink_name);
        metrics::record_runtime_failure_cause(kind, group_name, uplink_name, failure_cause);
        metrics::record_runtime_failure_signature(kind, group_name, uplink_name, failure_signature);
        if let Some(detail) = failure_other_detail {
            metrics::record_runtime_failure_other_detail(kind, group_name, uplink_name, detail);
        }
    } else {
        metrics::record_runtime_failure_suppressed(kind, group_name, uplink_name);
    }
}

impl UplinkManager {
    pub async fn runtime_failure_debug_state(
        &self,
        index: usize,
        transport: TransportKind,
    ) -> (Option<u128>, Option<u128>) {
        let now = Instant::now();
        if index >= self.inner.statuses.len() {
            return (None, None);
        }
        let status = self.inner.read_status(index);

        match transport {
            TransportKind::Tcp => (
                status
                    .tcp
                    .cooldown_until
                    .map(|deadline| deadline.saturating_duration_since(now).as_millis()),
                current_penalty(&status.tcp.penalty, now, &self.inner.load_balancing)
                    .map(|value| value.as_millis()),
            ),
            TransportKind::Udp => (
                status
                    .udp
                    .cooldown_until
                    .map(|deadline| deadline.saturating_duration_since(now).as_millis()),
                current_penalty(&status.udp.penalty, now, &self.inner.load_balancing)
                    .map(|value| value.as_millis()),
            ),
        }
    }

    pub async fn tcp_cooldown_debug_summary(&self) -> Vec<String> {
        let now = Instant::now();
        self.inner
            .uplinks
            .iter()
            .enumerate()
            .map(|(index, uplink)| {
                let status = self.inner.read_status(index);
                let cooldown_ms = status
                    .tcp
                    .cooldown_until
                    .map(|deadline| deadline.saturating_duration_since(now).as_millis())
                    .unwrap_or(0);
                let penalty_ms =
                    current_penalty(&status.tcp.penalty, now, &self.inner.load_balancing)
                        .map(|value| value.as_millis())
                        .unwrap_or(0);
                format!(
                    "{}#{}(healthy={:?},cooldown_ms={},penalty_ms={},last_error={})",
                    uplink.name,
                    index,
                    status.tcp.healthy,
                    cooldown_ms,
                    penalty_ms,
                    status.last_error.as_deref().unwrap_or("-")
                )
            })
            .collect()
    }

    pub async fn report_runtime_failure(
        &self,
        index: usize,
        transport: TransportKind,
        error: &anyhow::Error,
    ) {
        let failure_cause = classify_runtime_failure_cause(error);
        let failure_signature = classify_runtime_failure_signature(error);
        let error_text = format!("{error:#}");
        let failure_other_detail = (failure_signature == "other")
            .then(|| metrics::normalize_other_runtime_failure_detail(&error_text));
        let now = Instant::now();
        let uplink_name = self.inner.uplinks[index].name.clone();
        let group_name = self.inner.group_name.clone();
        // Read pre-mutation state to determine already_in_cooldown.
        let already_in_cooldown = {
            let s = self.inner.read_status(index);
            match transport {
                TransportKind::Tcp => s.tcp.cooldown_until.is_some_and(|d| d > now),
                TransportKind::Udp => s.udp.cooldown_until.is_some_and(|d| d > now),
            }
        };
        let probe_enabled = self.inner.probe.enabled();
        let failure_cooldown = self.inner.load_balancing.failure_cooldown;
        let load_balancing = self.inner.load_balancing.clone();
        // Same threshold the probe uses to flip `healthy`. Reusing it keeps
        // operator expectations consistent: "after N failed attempts the uplink
        // is considered down" applies to both signals.
        let runtime_failure_threshold = self.inner.probe.min_failures.max(1) as u32;
        // Time-decay for the runtime-failure streak: a new failure that arrives
        // more than `runtime_failure_window` after the previous one starts a
        // fresh streak (counter reset to 1) instead of stacking onto an old
        // one. Without this, sparse transient errors on a low-traffic uplink
        // accumulate indefinitely (the counter only resets on real data
        // transfer or a successful probe), so two unrelated errors minutes
        // apart escalate to a spurious `healthy = Some(false)` flip and the
        // active uplink flaps through the whole pool.
        // `Duration::ZERO` disables decay (legacy behaviour) for callers that
        // explicitly want it.
        let runtime_failure_window = self.inner.load_balancing.runtime_failure_window;
        // Data-plane failures only escalate to a health flip when the probe is
        // the authoritative signal AND we are in strict global mode — that is
        // the configuration where `should_keep` ignores cooldown, so without an
        // explicit health flip the active uplink would never lose its slot
        // until the slow probe cycle catches up.
        let runtime_health_escalation = probe_enabled && self.strict_global_active_uplink();

        let kind = match transport {
            TransportKind::Tcp => "tcp",
            TransportKind::Udp => "udp",
        };
        emit_runtime_failure_metrics(
            kind,
            &group_name,
            &uplink_name,
            failure_cause,
            failure_signature,
            failure_other_detail.as_deref(),
            already_in_cooldown,
        );

        // Apply mutation under the per-uplink lock.
        self.inner.with_status_mut(index, |status| {
            status.last_error = Some(error_text.clone());
            match transport {
                TransportKind::Tcp => {
                    if !already_in_cooldown {
                        if !probe_enabled {
                            add_penalty(&mut status.tcp.penalty, now, &load_balancing);
                        }
                        status.tcp.cooldown_until = Some(now + failure_cooldown);
                    }
                    // When probe is enabled it is the authoritative source of
                    // tcp_healthy.  A single runtime connection failure is not
                    // sufficient evidence that the server is down — only the probe
                    // can confirm that.  Setting tcp_healthy here would cause a
                    // global-scope failover on every transient error, which is exactly
                    // what we want to avoid.  When probe is disabled there is no other
                    // health signal, so fall back to marking the uplink unhealthy
                    // immediately so that cooldown-based gating can still trigger a switch.
                    if !probe_enabled {
                        status.tcp.healthy = Some(false);
                    }
                    // Track consecutive data-plane failures separately from probe
                    // failures so that under strict global + probe-enabled the
                    // dispatch path can escalate to a health flip after enough
                    // back-to-back failures, without waiting up to two probe
                    // cycles for the slow signal to confirm what every new
                    // connection is already observing.
                    let stale_streak = !runtime_failure_window.is_zero()
                        && status
                            .tcp
                            .last_runtime_failure_at
                            .is_some_and(|t| now.saturating_duration_since(t) > runtime_failure_window);
                    if stale_streak {
                        status.tcp.consecutive_runtime_failures = 1;
                    } else {
                        status.tcp.consecutive_runtime_failures =
                            status.tcp.consecutive_runtime_failures.saturating_add(1);
                    }
                    status.tcp.last_runtime_failure_at = Some(now);
                    if runtime_health_escalation
                        && status.tcp.consecutive_runtime_failures >= runtime_failure_threshold
                    {
                        status.tcp.healthy = Some(false);
                    }
                    if probe_enabled && !already_in_cooldown {
                        mark_probe_wakeup(
                            &mut status.tcp.last_probe_wakeup,
                            now,
                            PROBE_WAKEUP_MIN_INTERVAL,
                        );
                    }
                },
                TransportKind::Udp => {
                    if !already_in_cooldown {
                        // Same rationale as TCP above: when probe is enabled, defer
                        // penalty to the probe confirmation path to avoid inflating
                        // the score of a healthy-but-loaded uplink.
                        if !probe_enabled {
                            add_penalty(&mut status.udp.penalty, now, &load_balancing);
                        }
                        status.udp.cooldown_until = Some(now + failure_cooldown);
                    }
                    if !probe_enabled {
                        status.udp.healthy = Some(false);
                    }
                    let stale_streak = !runtime_failure_window.is_zero()
                        && status
                            .udp
                            .last_runtime_failure_at
                            .is_some_and(|t| now.saturating_duration_since(t) > runtime_failure_window);
                    if stale_streak {
                        status.udp.consecutive_runtime_failures = 1;
                    } else {
                        status.udp.consecutive_runtime_failures =
                            status.udp.consecutive_runtime_failures.saturating_add(1);
                    }
                    status.udp.last_runtime_failure_at = Some(now);
                    if runtime_health_escalation
                        && status.udp.consecutive_runtime_failures >= runtime_failure_threshold
                    {
                        status.udp.healthy = Some(false);
                    }
                    if probe_enabled && !already_in_cooldown {
                        mark_probe_wakeup(
                            &mut status.udp.last_probe_wakeup,
                            now,
                            PROBE_WAKEUP_MIN_INTERVAL,
                        );
                    }
                },
            }
        });
        // Read back post-mutation state for logging / wakeup decision.
        let (cooldown_until, penalty_ms, should_wake_probe) = {
            let status = self.inner.read_status(index);
            let load_balancing = &self.inner.load_balancing;
            match transport {
                TransportKind::Tcp => (
                    status.tcp.cooldown_until,
                    current_penalty(&status.tcp.penalty, now, load_balancing)
                        .map(|v| v.as_millis()),
                    probe_enabled
                        && !already_in_cooldown
                        && status
                            .tcp
                            .last_probe_wakeup
                            .is_some_and(|t| now.duration_since(t) < PROBE_WAKEUP_MIN_INTERVAL),
                ),
                TransportKind::Udp => (
                    status.udp.cooldown_until,
                    current_penalty(&status.udp.penalty, now, load_balancing)
                        .map(|v| v.as_millis()),
                    probe_enabled
                        && !already_in_cooldown
                        && status
                            .udp
                            .last_probe_wakeup
                            .is_some_and(|t| now.duration_since(t) < PROBE_WAKEUP_MIN_INTERVAL),
                ),
            }
        };

        let cooldown_ms = cooldown_until
            .map(|deadline| deadline.saturating_duration_since(Instant::now()).as_millis());
        if already_in_cooldown {
            debug!(
                uplink = %uplink_name,
                uplink_index = index,
                transport = ?transport,
                cooldown_ms,
                penalty_ms,
                error = %format!("{error:#}"),
                "runtime uplink failure observed while uplink is already in cooldown"
            );
        } else {
            warn!(
                uplink = %uplink_name,
                uplink_index = index,
                transport = ?transport,
                cooldown_ms,
                penalty_ms,
                error = %format!("{error:#}"),
                "runtime uplink failure recorded"
            );
            // Wake the probe loop immediately so it can confirm the failure
            // without waiting for the next scheduled interval.
            if should_wake_probe {
                metrics::record_probe_wakeup(
                    &self.inner.group_name,
                    &uplink_name,
                    kind,
                    "runtime_failure",
                    "sent",
                );
                self.inner.probe_wakeup.notify_one();
            } else if self.inner.probe.enabled() {
                metrics::record_probe_wakeup(
                    &self.inner.group_name,
                    &uplink_name,
                    kind,
                    "runtime_failure",
                    "suppressed",
                );
                debug!(
                    uplink = %uplink_name,
                    uplink_index = index,
                    transport = ?transport,
                    min_interval_secs = PROBE_WAKEUP_MIN_INTERVAL.as_secs(),
                    "probe wakeup suppressed by runtime-failure rate limit"
                );
            }
        }

        // Apply H3 → H2 downgrade for this transport kind.
        self.extend_mode_downgrade(index, transport, ModeDowngradeTrigger::RuntimeFailure(error));

        self.clear_standby(index, transport).await;
    }

    pub async fn runtime_failure_probe_wakeup_debug_state(
        &self,
        index: usize,
        transport: TransportKind,
    ) -> Option<u128> {
        let now = Instant::now();
        if index >= self.inner.statuses.len() {
            return None;
        }
        let status = self.inner.read_status(index);
        match transport {
            TransportKind::Tcp => status
                .tcp
                .last_probe_wakeup
                .map(|t| now.saturating_duration_since(t).as_millis()),
            TransportKind::Udp => status
                .udp
                .last_probe_wakeup
                .map(|t| now.saturating_duration_since(t).as_millis()),
        }
    }

    /// Called when real traffic successfully flows through an uplink.
    ///
    /// Updates the activity timestamp (rate-limited to once per 5 s to keep
    /// write-lock contention low for high-frequency UDP callers), marks the
    /// transport as healthy, resets consecutive-failure counters, and clears
    /// any active failure cooldown.  A successful data transfer is stronger
    /// evidence of liveness than a probe ping/pong, so we treat it
    /// accordingly.
    pub async fn report_active_traffic(&self, index: usize, transport: TransportKind) {
        let now = Instant::now();
        // Fast path: skip the write lock when we recently reported for this transport.
        {
            let s = self.inner.read_status(index);
            let last = match transport {
                TransportKind::Tcp => s.tcp.last_active,
                TransportKind::Udp => s.udp.last_active,
            };
            if last.is_some_and(|t| now.duration_since(t) < Duration::from_secs(5)) {
                return;
            }
        }
        let uplink_name = self.inner.uplinks[index].name.clone();
        // Double-check after acquiring the write lock to avoid a race where
        // two callers both pass the fast-path read.
        let probe_enabled = self.inner.probe.enabled();
        let mut did_update = false;
        self.inner.with_status_mut(index, |status| {
            let last = match transport {
                TransportKind::Tcp => &mut status.tcp.last_active,
                TransportKind::Udp => &mut status.udp.last_active,
            };
            if last.is_some_and(|t| now.duration_since(t) < Duration::from_secs(5)) {
                return;
            }
            *last = Some(now);
            did_update = true;
            // When probe is enabled it is the authoritative source of tcp_healthy /
            // udp_healthy.  Overriding it here would let an in-flight session on a
            // probe-marked-unhealthy uplink keep resetting the health flag to
            // Some(true), preventing the failover from taking effect in
            // active-passive / global scope.  When probe is disabled there is no
            // other health signal, so we update the health state from traffic.
            match transport {
                TransportKind::Tcp => {
                    // Real data flowing on this transport invalidates the
                    // runtime-failure streak regardless of who owns the health
                    // bit — even when probe is authoritative, we should not
                    // escalate to a health flip while the data path is alive.
                    status.tcp.consecutive_runtime_failures = 0;
                    if !probe_enabled {
                        status.tcp.healthy = Some(true);
                        status.tcp.consecutive_failures = 0;
                        // When probe is disabled active traffic is the only health
                        // signal, so clear the cooldown immediately.
                        status.tcp.cooldown_until = None;
                    }
                    // When probe is enabled it is the authoritative source of health.
                    // Do not clear the cooldown from in-flight traffic: a session
                    // that was established *before* a runtime failure and is still
                    // exchanging data does not prove the uplink is healthy for *new*
                    // sessions.  The probe wakeup fired at failure time will clear
                    // the cooldown within seconds once it confirms connectivity.
                    // Clearing it here would let new sessions route to a recently-
                    // failed uplink before the probe has had a chance to confirm.
                },
                TransportKind::Udp => {
                    status.udp.consecutive_runtime_failures = 0;
                    if !probe_enabled {
                        status.udp.healthy = Some(true);
                        status.udp.consecutive_failures = 0;
                        status.udp.cooldown_until = None;
                    }
                },
            }
        });
        if !did_update {
            return;
        }
        debug!(
            uplink = %uplink_name,
            transport = ?transport,
            "real traffic activity recorded"
        );
    }

    /// Called when the upstream WebSocket closes unexpectedly mid-session
    /// (server-initiated close, not a client disconnect).  Does not set a
    /// full runtime-failure cooldown — that would penalise the uplink for
    /// normal per-connection lifetime limits — but clears the activity
    /// timestamp so that the next probe cycle is not skipped.  This ensures
    /// the probe detects a downed server promptly instead of waiting for
    /// `probe.interval` of silence.
    ///
    /// Exception: when traffic was active very recently (within
    /// `failure_cooldown`), the timestamp is preserved.  Under load servers
    /// close connections frequently due to per-connection lifetime limits;
    /// clearing the timestamp each time would force probe cycles during the
    /// busiest moments, which risks false-negative health readings and
    /// spurious failovers.  The scheduled probe interval provides a more
    /// reliable signal once the burst subsides.
    pub async fn report_upstream_close(&self, index: usize, transport: TransportKind) {
        let now = Instant::now();
        let threshold = self.inner.load_balancing.failure_cooldown;
        self.inner.with_status_mut(index, |status| match transport {
            TransportKind::Tcp => {
                let recently_active = status
                    .tcp
                    .last_active
                    .is_some_and(|t| now.duration_since(t) < threshold);
                if !recently_active {
                    status.tcp.last_active = None;
                }
            },
            TransportKind::Udp => {
                let recently_active = status
                    .udp
                    .last_active
                    .is_some_and(|t| now.duration_since(t) < threshold);
                if !recently_active {
                    status.udp.last_active = None;
                }
            },
        });
    }

    /// Feed a connection-establishment latency sample into the RTT EWMA for
    /// the given uplink and transport.  Called when a fresh (non-standby)
    /// WebSocket connection is established so that real path quality is
    /// reflected in routing scores alongside probe-derived measurements.
    pub async fn report_connection_latency(
        &self,
        index: usize,
        transport: TransportKind,
        latency: Duration,
    ) {
        let alpha = self.inner.load_balancing.rtt_ewma_alpha;
        self.inner.with_status_mut(index, |status| match transport {
            TransportKind::Tcp => {
                update_rtt_ewma(&mut status.tcp.rtt_ewma, Some(latency), alpha);
            },
            TransportKind::Udp => {
                update_rtt_ewma(&mut status.udp.rtt_ewma, Some(latency), alpha);
            },
        });
    }
}
