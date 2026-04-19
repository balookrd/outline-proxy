use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, warn};

use outline_metrics as metrics;
use crate::config::UplinkTransport;

use super::super::types::{TransportKind, UplinkManager};
use super::super::utils::{
    add_penalty, classify_runtime_failure_cause, classify_runtime_failure_signature,
    current_penalty, mark_probe_wakeup, normalize_other_runtime_failure_detail, update_rtt_ewma,
};

const PROBE_WAKEUP_MIN_INTERVAL: Duration = Duration::from_secs(15);

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
        let statuses = self.inner.snapshot_statuses();
        self.inner
            .uplinks
            .iter()
            .enumerate()
            .map(|(index, uplink)| {
                let status = &statuses[index];
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
            .then(|| normalize_other_runtime_failure_detail(&error_text));
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
        // Emit metrics (does not require the lock).
        match transport {
            TransportKind::Tcp => {
                if !already_in_cooldown {
                    metrics::record_runtime_failure("tcp", &group_name, &uplink_name);
                    metrics::record_runtime_failure_cause("tcp", &group_name, &uplink_name, failure_cause);
                    metrics::record_runtime_failure_signature("tcp", &group_name, &uplink_name, failure_signature);
                    if let Some(detail) = &failure_other_detail {
                        metrics::record_runtime_failure_other_detail("tcp", &group_name, &uplink_name, detail);
                    }
                } else {
                    metrics::record_runtime_failure_suppressed("tcp", &group_name, &uplink_name);
                }
            },
            TransportKind::Udp => {
                if !already_in_cooldown {
                    metrics::record_runtime_failure("udp", &group_name, &uplink_name);
                    metrics::record_runtime_failure_cause("udp", &group_name, &uplink_name, failure_cause);
                    metrics::record_runtime_failure_signature("udp", &group_name, &uplink_name, failure_signature);
                    if let Some(detail) = &failure_other_detail {
                        metrics::record_runtime_failure_other_detail("udp", &group_name, &uplink_name, detail);
                    }
                } else {
                    metrics::record_runtime_failure_suppressed("udp", &group_name, &uplink_name);
                }
            },
        }
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
                        && status.tcp.last_probe_wakeup.is_some_and(|t| {
                            now.duration_since(t) < PROBE_WAKEUP_MIN_INTERVAL
                        }),
                ),
                TransportKind::Udp => (
                    status.udp.cooldown_until,
                    current_penalty(&status.udp.penalty, now, load_balancing)
                        .map(|v| v.as_millis()),
                    probe_enabled
                        && !already_in_cooldown
                        && status.udp.last_probe_wakeup.is_some_and(|t| {
                            now.duration_since(t) < PROBE_WAKEUP_MIN_INTERVAL
                        }),
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
                    match transport {
                        TransportKind::Tcp => "tcp",
                        TransportKind::Udp => "udp",
                    },
                    "runtime_failure",
                    "sent",
                );
                self.inner.probe_wakeup.notify_one();
            } else if self.inner.probe.enabled() {
                metrics::record_probe_wakeup(
                    &self.inner.group_name,
                    &uplink_name,
                    match transport {
                        TransportKind::Tcp => "tcp",
                        TransportKind::Udp => "udp",
                    },
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
        // If the uplink is configured for H3 and a TCP connection failed at
        // runtime for any reason, mark H3 as temporarily broken so subsequent
        // connections use H2 instead.
        //
        // Previously this was gated on specific APPLICATION_CLOSE error codes
        // (H3_INTERNAL_ERROR, etc.), but H3/QUIC connections can fail with
        // many other errors (connection lost, transport error, stream reset,
        // QUIC timeout, …) that would leave the downgrade timer unset and
        // cause repeated cooldown-driven flapping:
        //   cooldown expires → try H3 → non-APPLICATION_CLOSE error → cooldown →
        //   switch to backup → cooldown expires → try H3 again → repeat.
        // Triggering the downgrade on any TCP failure is safe: if the server
        // is genuinely down both H3 and H2 will fail and we failover to another
        // uplink regardless.  Recovery is natural: once h3_downgrade_duration
        // elapses the next real connection re-tests H3.
        if matches!(transport, TransportKind::Tcp) {
            let uplink = &self.inner.uplinks[index];
            if uplink.transport == UplinkTransport::Websocket
                && uplink.tcp_ws_mode == crate::config::WsTransportMode::H3
            {
                let now = tokio::time::Instant::now();
                let h3_downgrade_duration = self.inner.load_balancing.h3_downgrade_duration;
                let prev = self.inner.read_status(index).tcp.h3_downgrade_until;
                if prev.is_none_or(|t| t < now) {
                    warn!(
                        uplink = %uplink.name,
                        error = %format!("{error:#}"),
                        downgrade_secs = h3_downgrade_duration.as_secs(),
                        "H3 TCP runtime error detected, downgrading TCP transport to H2"
                    );
                }
                let downgrade_until = now + h3_downgrade_duration;
                self.inner.with_status_mut(index, |status| {
                    status.tcp.h3_downgrade_until = Some(downgrade_until);
                });
            }
        }
        // Same downgrade logic for UDP transport.  Without this, a broken H3
        // server would cause UDP failover to spin in a tight loop when there
        // is only one (or only one healthy) uplink: each new UDP transport
        // dials H3, fails on the first packet with APPLICATION_CLOSE, and
        // re-triggers failover.  Downgrading to H2 for h3_downgrade_duration
        // breaks the loop until the downgrade timer expires (or the H3
        // recovery probe confirms H3 is back).
        if matches!(transport, TransportKind::Udp) {
            let uplink = &self.inner.uplinks[index];
            if uplink.transport == UplinkTransport::Websocket
                && uplink.udp_ws_mode == crate::config::WsTransportMode::H3
            {
                let now = tokio::time::Instant::now();
                let h3_downgrade_duration = self.inner.load_balancing.h3_downgrade_duration;
                let prev = self.inner.read_status(index).udp.h3_downgrade_until;
                if prev.is_none_or(|t| t < now) {
                    warn!(
                        uplink = %uplink.name,
                        error = %format!("{error:#}"),
                        downgrade_secs = h3_downgrade_duration.as_secs(),
                        "H3 UDP runtime error detected, downgrading UDP transport to H2"
                    );
                }
                let downgrade_until = now + h3_downgrade_duration;
                self.inner.with_status_mut(index, |status| {
                    status.udp.h3_downgrade_until = Some(downgrade_until);
                });
            }
        }
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
